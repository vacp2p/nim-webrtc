# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import tables, bitops, nativesockets, strutils
import usrsctp, chronos, chronicles
import
  ./[sctp_connection, sctp_utils], ../errors, ../dtls/[dtls_transport, dtls_connection]

export chronicles

const
  SctpEINPROGRESS =
    when defined(windows):
      import winlean
      winlean.WSAEINPROGRESS.cint
    else:
      chronos.EINPROGRESS.cint
  SctpTransportTracker* = "webrtc.sctp.transport"
  IPPROTO_SCTP = 132

logScope:
  topics = "webrtc sctp"

# Implementation of an Sctp client and server using the usrsctp library.
# Usrsctp is usable as a single thread but it's not the intended way to
# use it. There's a lot of callbacks calling each other in a synchronous
# way where we want to be able to call asynchronous procedure, but cannot.

# TODO:
# - Replace doAssert by a proper exception management
# - Find a clean way to manage SCTP ports

var errno {.importc, header: "<errno.h>".}: cint ## error variable
proc printf(
  format: cstring
) {.cdecl, importc: "printf", varargs, header: "<stdio.h>", gcsafe.}

type Sctp* = ref object
  dtls: Dtls
  connections: Table[TransportAddress, SctpConn]
  gotConnection: AsyncEvent
  isServer: bool
  sockServer: ptr socket
  pendingConnections: seq[SctpConn]
  sentFuture: Future[void].Raising([CancelledError])

# -- usrsctp accept and connect callbacks --

proc handleAccept(sock: ptr socket, data: pointer, flags: cint) {.cdecl.} =
  # Callback procedure called when accepting a connection
  trace "Handle Accept"
  var
    sconn: Sockaddr_conn
    slen: Socklen = sizeof(Sockaddr_conn).uint32
  let
    sctp = cast[Sctp](data)
    sctpSocket =
      usrsctp_accept(sctp.sockServer, cast[ptr SockAddr](addr sconn), addr slen)
    conn = cast[SctpConn](sconn.sconn_addr)

  if sctpSocket.isNil():
    warn "usrsctp_accept fails", error = sctpStrerror(errno)
    conn.state = SctpState.SctpClosed
  else:
    conn.sctpSocket = sctpSocket
    conn.state = SctpState.SctpConnected
  conn.acceptEvent.fire()

proc handleConnect(sock: ptr socket, data: pointer, flags: cint) {.cdecl.} =
  # Callback procedure called during usrsctp_connect
  let
    conn = cast[SctpConn](data)
    events = usrsctp_get_events(sock)

  trace "Handle Connect", events, state = conn.state
  if conn.state == SctpState.SctpConnecting:
    if bitand(events, SCTP_EVENT_ERROR) != 0:
      warn "Cannot connect", raddr = conn.remoteAddress()
      conn.state = SctpState.SctpClosed
    elif bitand(events, SCTP_EVENT_WRITE) != 0:
      conn.state = SctpState.SctpConnected
      doAssert 0 == usrsctp_set_upcall(conn.sctpSocket, recvCallback, data)
    conn.connectEvent.fire()
  else:
    warn "should be connecting", currentState = conn.state

# -- Sctp --

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
  self.dtls = dtls

  usrsctp_init_nothreads(dtls.localAddress.port.uint16, sendCallback, printf)
  discard usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_ALL.uint32)
  discard usrsctp_sysctl_set_sctp_ecn_enable(1)
  trackCounter(SctpTransportTracker)
  return self

proc close*(self: Sctp) {.async: (raises: [CancelledError]).} =
  # TODO: close every connections
  untrackCounter(SctpTransportTracker)
  discard self.usrsctpAwait usrsctp_finish()

proc readLoopProc(res: SctpConn) {.async: (raises: [CancelledError, WebRtcError]).} =
  while true:
    let msg = await res.conn.read()
    if msg == @[]:
      trace "Sctp read loop stopped, DTLS connection closed"
      return
    trace "Receive data",
      remoteAddress = res.conn.remoteAddress(), sctPacket = $(msg.getSctpPacket())
    usrsctp_conninput(cast[pointer](res), unsafeAddr msg[0], uint(msg.len), 0)

proc socketSetup(
    conn: SctpConn, callback: proc(a1: ptr socket, a2: pointer, a3: cint) {.cdecl.}
): bool =
  var
    errorCode = conn.sctpSocket.usrsctp_set_non_blocking(1)
    nodelay: uint32 = 1
    recvinfo: uint32 = 1

  if errorCode != 0:
    warn "usrsctp_set_non_blocking fails", error = sctpStrerror(errorCode)
    return false

  errorCode = conn.sctpSocket.usrsctp_set_upcall(callback, cast[pointer](conn))
  if errorCode != 0:
    warn "usrsctp_set_upcall fails", error = sctpStrerror(errorCode)
    return false

  errorCode = conn.sctpSocket.usrsctp_setsockopt(
    IPPROTO_SCTP, SCTP_NODELAY, addr nodelay, sizeof(nodelay).SockLen
  )
  if errorCode != 0:
    warn "usrsctp_setsockopt nodelay fails", error = sctpStrerror(errorCode)
    return false

  errorCode = conn.sctpSocket.usrsctp_setsockopt(
    IPPROTO_SCTP, SCTP_RECVRCVINFO, addr recvinfo, sizeof(recvinfo).SockLen
  )
  if errorCode != 0:
    warn "usrsctp_setsockopt recvinfo fails", error = sctpStrerror(errorCode)
    return false
  return true

proc accept*(
    self: Sctp
): Future[SctpConn] {.async: (raises: [CancelledError, WebRtcError]).} =
  ## Accept an Sctp Connection
  ##
  if not self.isServer:
    raise newException(WebRtcError, "SCTP - Not a server")
  trace "Accept connection"
  var conn: SctpConn
  while true:
    conn = SctpConn.new(await self.dtls.accept())
    usrsctp_register_address(cast[pointer](conn))
    conn.readLoop = conn.readLoopProc()
    conn.acceptEvent.clear()
    await conn.acceptEvent.wait()
    if conn.state == SctpState.SctpConnected and conn.socketSetup(recvCallback):
      break
    await conn.close()

  self.connections[conn.remoteAddress()] = conn
  trackCounter(SctpConnTracker)
  return conn

proc listen*(self: Sctp, sctpPort: uint16 = 5000) =
  if self.isServer:
    trace "Try to start the server twice"
    return
  self.isServer = true
  trace "Listening", sctpPort
  doAssert 0 == usrsctp_sysctl_set_sctp_blackhole(2)
  doAssert 0 == usrsctp_sysctl_set_sctp_no_csum_on_loopback(0)
  doAssert 0 == usrsctp_sysctl_set_sctp_delayed_sack_time_default(0)
  let sock = usrsctp_socket(AF_CONN, SOCK_STREAM.toInt(), IPPROTO_SCTP, nil, nil, 0, nil)
  var on: int = 1
  doAssert 0 == usrsctp_set_non_blocking(sock, 1)
  var sin: Sockaddr_in
  sin.sin_family = type(sin.sin_family)(AF_INET)
  sin.sin_port = htons(sctpPort)
  sin.sin_addr.s_addr = htonl(INADDR_ANY)
  doAssert 0 ==
    usrsctp_bind(sock, cast[ptr SockAddr](addr sin), SockLen(sizeof(Sockaddr_in)))
  doAssert 0 >= usrsctp_listen(sock, 1)
  doAssert 0 == sock.usrsctp_set_upcall(handleAccept, cast[pointer](self))
  self.sockServer = sock

proc connect*(
    self: Sctp, raddr: TransportAddress, sctpPort: uint16 = 5000
): Future[SctpConn] {.async: (raises: [CancelledError, WebRtcError]).} =
  trace "Create Connection", raddr
  let conn = SctpConn.new(await self.dtls.connect(raddr))
  conn.state = SctpState.SctpConnecting
  conn.sctpSocket =
    usrsctp_socket(AF_CONN, SOCK_STREAM.toInt(), IPPROTO_SCTP, nil, nil, 0, nil)

  if not conn.socketSetup(handleConnect):
    raise newException(WebRtcError, "SCTP - Socket setup failed while connecting")

  var sconn: Sockaddr_conn
  sconn.sconn_family = AF_CONN
  sconn.sconn_port = htons(sctpPort)
  sconn.sconn_addr = cast[pointer](conn)
  usrsctp_register_address(cast[pointer](conn))
  conn.readLoop = conn.readLoopProc()

  let connErr = self.usrsctpAwait:
    conn.sctpSocket.usrsctp_connect(
      cast[ptr SockAddr](addr sconn), SockLen(sizeof(sconn))
    )
  if connErr != 0 and errno != SctpEINPROGRESS:
    raise
      newException(WebRtcError, "SCTP - Connection failed: " & $(sctpStrerror(errno)))

  conn.connectEvent.clear()
  await conn.connectEvent.wait()
  if conn.state == SctpState.SctpClosed:
    raise newException(WebRtcError, "SCTP - Connection failed")
  self.connections[raddr] = conn
  trackCounter(SctpConnTracker)
  return conn
