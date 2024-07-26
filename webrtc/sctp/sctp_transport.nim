# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import tables, posix, strutils, sequtils
import chronos, chronicles, stew/[ranges/ptr_arith, endians2]
import usrsctp
import ../errors
import ../dtls/[dtls_transport, dtls_connection]
import ./[sctp_connection, sctp_utils]
import binary_serialization

export chronicles

logScope:
  topics = "webrtc sctp"

# Implementation of an Sctp client and server using the usrsctp library.
# Usrsctp is usable as a single thread but it's not the intended way to
# use it. There's a lot of callbacks calling each other in a synchronous
# way where we want to be able to call asynchronous procedure, but cannot.

# TODO:
# - Replace doAssert by a proper exception management
# - Find a clean way to manage SCTP ports

proc printf(format: cstring) {.cdecl, importc: "printf", varargs, header: "<stdio.h>", gcsafe.}

type
  Sctp* = ref object
    dtls: Dtls
    laddr*: TransportAddress
    connections: Table[TransportAddress, SctpConn]
    gotConnection: AsyncEvent
    timersHandler: Future[void]
    isServer: bool
    sockServer: ptr socket
    pendingConnections: seq[SctpConn]
    pendingConnections2: Table[SockAddr, SctpConn]
    sentFuture: Future[void]

const IPPROTO_SCTP = 132

# -- usrsctp receive data callbacks --

proc handleAccept(sock: ptr socket, data: pointer, flags: cint) {.cdecl.} =
  # Callback procedure called when accepting a connection.
  trace "Handle Accept"
  var
    sconn: Sockaddr_conn
    slen: Socklen = sizeof(Sockaddr_conn).uint32
  let
    sctp = cast[Sctp](data)
    # TODO: check if sctpSocket != nil
    sctpSocket = usrsctp_accept(sctp.sockServer, cast[ptr SockAddr](addr sconn), addr slen)

  let conn = cast[SctpConn](sconn.sconn_addr)
  conn.sctpSocket = sctpSocket
  conn.state = Connected
  var nodelay: uint32 = 1
  var recvinfo: uint32 = 1
  doAssert 0 == sctpSocket.usrsctp_set_non_blocking(1)
  doAssert 0 == conn.sctpSocket.usrsctp_set_upcall(recvCallback, cast[pointer](conn))
  doAssert 0 == conn.sctpSocket.usrsctp_setsockopt(IPPROTO_SCTP, SCTP_NODELAY,
                                 addr nodelay, sizeof(nodelay).SockLen)
  doAssert 0 == conn.sctpSocket.usrsctp_setsockopt(IPPROTO_SCTP, SCTP_RECVRCVINFO,
                                 addr recvinfo, sizeof(recvinfo).SockLen)
  conn.acceptEvent.fire()

proc handleConnect(sock: ptr socket, data: pointer, flags: cint) {.cdecl.} =
  # Callback procedure called when connecting
  trace "Handle Connect"
  let
    conn = cast[SctpConn](data)
    events = usrsctp_get_events(sock)

  trace "Handle Upcall", events, state = conn.state
  if conn.state == Connecting:
    if bitand(events, SCTP_EVENT_ERROR) != 0:
      warn "Cannot connect", address = conn.address
      conn.state = Closed
    elif bitand(events, SCTP_EVENT_WRITE) != 0:
      conn.state = Connected
      doAssert 0 == usrsctp_set_upcall(conn.sctpSocket, recvCallback, data)
    conn.connectEvent.fire()
  else:
    warn "should be connecting", currentState = conn.state

# -- Sctp --

proc timersHandler() {.async.} =
  while true:
    await sleepAsync(500.milliseconds)
    usrsctp_handle_timers(500)

proc stopServer*(self: Sctp) =
  if not self.isServer:
    trace "Try to close a client"
    return
  self.isServer = false
  let pcs = self.pendingConnections
  self.pendingConnections = @[]
  for pc in pcs:
    pc.sctpSocket.usrsctp_close()
  self.sockServer.usrsctp_close()

proc new*(T: type Sctp, dtls: Dtls): T =
  var self = T()
  self.gotConnection = newAsyncEvent()
  self.timersHandler = timersHandler()
  self.dtls = dtls

  usrsctp_init_nothreads(dtls.laddr.port.uint16, sendCallback, printf)
  discard usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_NONE)
  discard usrsctp_sysctl_set_sctp_ecn_enable(1)
  usrsctp_register_address(cast[pointer](self))
  return self

proc stop*(self: Sctp) {.async.} =
  # TODO: close every connections
  discard self.usrsctpAwait usrsctp_finish()

proc readLoopProc(res: SctpConn) {.async.} =
  while true:
    let
      msg = await res.conn.read()
      data = usrsctp_dumppacket(unsafeAddr msg[0], uint(msg.len), SCTP_DUMP_INBOUND)
    if not data.isNil():
      trace "Receive data", remoteAddress = res.conn.raddr,
            sctpPacket = data.getSctpPacket()
      usrsctp_freedumpbuffer(data)
    usrsctp_conninput(cast[pointer](res), unsafeAddr msg[0], uint(msg.len), 0)

proc accept*(self: Sctp): Future[SctpConn] {.async.} =
  if not self.isServer:
    raise newException(WebRtcError, "SCTP - Not a server")
  var res = SctpConn.new(await self.dtls.accept())
  usrsctp_register_address(cast[pointer](res))
  res.readLoop = res.readLoopProc()
  res.acceptEvent.clear()
  await res.acceptEvent.wait()
  return res

proc listen*(self: Sctp, sctpPort: uint16 = 5000) =
  if self.isServer:
    trace "Try to start the server twice"
    return
  self.isServer = true
  trace "Listening", sctpPort
  doAssert 0 == usrsctp_sysctl_set_sctp_blackhole(2)
  doAssert 0 == usrsctp_sysctl_set_sctp_no_csum_on_loopback(0)
  doAssert 0 == usrsctp_sysctl_set_sctp_delayed_sack_time_default(0)
  let sock = usrsctp_socket(AF_CONN, posix.SOCK_STREAM, IPPROTO_SCTP, nil, nil, 0, nil)
  var on: int = 1
  doAssert 0 == usrsctp_set_non_blocking(sock, 1)
  var sin: Sockaddr_in
  sin.sin_family = posix.AF_INET.uint16
  sin.sin_port = htons(sctpPort)
  sin.sin_addr.s_addr = htonl(INADDR_ANY)
  doAssert 0 == usrsctp_bind(sock, cast[ptr SockAddr](addr sin), SockLen(sizeof(Sockaddr_in)))
  doAssert 0 >= usrsctp_listen(sock, 1)
  doAssert 0 == sock.usrsctp_set_upcall(handleAccept, cast[pointer](self))
  self.sockServer = sock

proc connect*(self: Sctp,
              address: TransportAddress,
              sctpPort: uint16 = 5000): Future[SctpConn] {.async.} =
  let
    sctpSocket = usrsctp_socket(AF_CONN, posix.SOCK_STREAM, IPPROTO_SCTP, nil, nil, 0, nil)
    conn = SctpConn.new(await self.dtls.connect(address))

  trace "Create Connection", address
  conn.sctpSocket = sctpSocket
  conn.state = Connected
  var nodelay: uint32 = 1
  var recvinfo: uint32 = 1
  doAssert 0 == usrsctp_set_non_blocking(conn.sctpSocket, 1)
  doAssert 0 == usrsctp_set_upcall(conn.sctpSocket, handleConnect, cast[pointer](conn))
  doAssert 0 == conn.sctpSocket.usrsctp_setsockopt(IPPROTO_SCTP, SCTP_NODELAY,
                                 addr nodelay, sizeof(nodelay).SockLen)
  doAssert 0 == conn.sctpSocket.usrsctp_setsockopt(IPPROTO_SCTP, SCTP_RECVRCVINFO,
                                 addr recvinfo, sizeof(recvinfo).SockLen)
  var sconn: Sockaddr_conn
  sconn.sconn_family = AF_CONN
  sconn.sconn_port = htons(sctpPort)
  sconn.sconn_addr = cast[pointer](conn)
  usrsctp_register_address(cast[pointer](conn))
  conn.readLoop = conn.readLoopProc()
  let connErr = self.usrsctpAwait:
    conn.sctpSocket.usrsctp_connect(cast[ptr SockAddr](addr sconn), SockLen(sizeof(sconn)))
  doAssert 0 == connErr or errno == posix.EINPROGRESS, ($errno)
  conn.state = Connecting
  conn.connectEvent.clear()
  await conn.connectEvent.wait()
  # TODO: check connection state, if closed throw an exception
  self.connections[address] = conn
  return conn
