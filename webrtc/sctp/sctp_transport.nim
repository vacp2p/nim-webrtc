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
  SctpTransportTracker* = "webrtc.sctp.transport"
  IPPROTO_SCTP = 132

logScope:
  topics = "webrtc sctp"

# Implementation of an Sctp client and server using the usrsctp library.
# Usrsctp is usable as a single thread but it's not the intended way to
# use it. There's a lot of callbacks calling each other in a synchronous way.

# TODO:
# - Find a clean way to manage SCTP ports

proc printf(
  format: cstring
) {.cdecl, importc: "printf", varargs, header: "<stdio.h>", gcsafe.}

type Sctp* = ref object
  dtls: Dtls # Underlying Dtls Transport
  connections: Table[TransportAddress, SctpConn] # List of all the Sctp connections
  isServer: bool
  sockServer: ptr socket # usrsctp socket to accept new connections

# -- usrsctp accept and connect callbacks --

proc handleAccept(sock: ptr socket, data: pointer, flags: cint) {.cdecl.} =
  # Callback procedure called when a connection is about to be accepted.
  var
    sconn: Sockaddr_conn
    slen: Socklen = sizeof(Sockaddr_conn).uint32
  let
    sctp = cast[Sctp](data)
    sctpSocket =
      usrsctp_accept(sctp.sockServer, cast[ptr SockAddr](addr sconn), addr slen)
    conn = cast[SctpConn](sconn.sconn_addr)

  if sctpSocket.isNil():
    warn "usrsctp_accept fails", error = sctpStrerror()
    conn.state = SctpState.SctpClosed
  else:
    trace "Scpt connection accepted", remoteAddress = conn.remoteAddress()
    conn.sctpSocket = sctpSocket
    conn.state = SctpState.SctpConnected
  conn.acceptEvent.fire()

proc handleConnect(sock: ptr socket, data: pointer, flags: cint) {.cdecl.} =
  # Callback procedure called during usrsctp_connect
  let
    conn = cast[SctpConn](data)
    events = usrsctp_get_events(sock)

  if conn.state == SctpState.SctpConnecting:
    if bitand(events, SCTP_EVENT_ERROR) != 0:
      warn "Cannot connect", remoteAddress = conn.remoteAddress()
      conn.state = SctpState.SctpClosed
    elif bitand(events, SCTP_EVENT_WRITE) != 0:
      conn.state = SctpState.SctpConnected
      if usrsctp_set_upcall(conn.sctpSocket, recvCallback, data) != 0:
        warn "usrsctp_set_upcall fails while connecting", error = sctpStrerror()
      trace "Sctp connection connected", remoteAddress = conn.remoteAddress()
    conn.connectEvent.fire()
  else:
    warn "Should never happen", currentState = conn.state

proc stopServer*(self: Sctp) =
  ## Sctp Transport stop acting like a server
  ##
  if not self.isServer:
    trace "Try to close a client"
    return
  self.isServer = false
  self.sockServer.usrsctp_close()

proc serverSetup(self: Sctp, sctpPort: uint16): bool =
  if usrsctp_sysctl_set_sctp_blackhole(2) != 0:
    warn "usrsctp_sysctl_set_sctp_blackhole fails", error = sctpStrerror()
    return false

  if usrsctp_sysctl_set_sctp_no_csum_on_loopback(0) != 0:
    warn "usrsctp_sysctl_set_sctp_no_csum_on_loopback fails", error = sctpStrerror()
    return false

  if usrsctp_sysctl_set_sctp_delayed_sack_time_default(0) != 0:
    warn "usrsctp_sysctl_set_sctp_delayed_sack_time_default fails", error = sctpStrerror()
    return false

  let sock = usrsctp_socket(AF_CONN, SOCK_STREAM.toInt(), IPPROTO_SCTP, nil, nil, 0, nil)
  if usrsctp_set_non_blocking(sock, 1) != 0:
    warn "usrsctp_set_non_blocking fails", error = sctpStrerror()
    return false

  var sin: Sockaddr_in
  sin.sin_family = type(sin.sin_family)(SctpAF_INET)
  sin.sin_port = htons(sctpPort)
  sin.sin_addr.s_addr = htonl(INADDR_ANY)
  if usrsctp_bind(sock, cast[ptr SockAddr](addr sin), SockLen(sizeof(Sockaddr_in))) != 0:
    warn "usrsctp_bind fails", error = sctpStrerror()
    return false

  if usrsctp_listen(sock, 1) < 0:
    warn "usrsctp_listen fails", error = sctpStrerror()
    return false

  if sock.usrsctp_set_upcall(handleAccept, cast[pointer](self)) != 0:
    warn "usrsctp_set_upcall fails", error = sctpStrerror()
    return false

  self.sockServer = sock
  return true

proc listen*(self: Sctp, sctpPort: uint16 = 5000) =
  ## listen marks the Sctp Transport as a transport that will be used to accept
  ## incoming connection requests using accept.
  ##
  if self.isServer:
    trace "Try to start the server twice"
    return
  self.isServer = true
  trace "Sctp listening", sctpPort
  if not self.serverSetup(sctpPort):
    raise newException(WebRtcError, "SCTP - Fails to listen")

proc new*(T: type Sctp, dtls: Dtls): T =
  var self = T()
  self.dtls = dtls

  when defined(windows):
    usrsctp_init_nothreads(dtls.localAddress.port.uint16, sendCallback, nil)
  else:
    usrsctp_init_nothreads(dtls.localAddress.port.uint16, sendCallback, printf)
  discard usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_ALL.uint32)
  discard usrsctp_sysctl_set_sctp_ecn_enable(1)
  trackCounter(SctpTransportTracker)
  return self

proc close*(self: Sctp) {.async: (raises: [CancelledError]).} =
  # TODO: close every connections
  untrackCounter(SctpTransportTracker)
  discard usrsctp_finish()

proc socketSetup(
    conn: SctpConn, callback: proc(a1: ptr socket, a2: pointer, a3: cint) {.cdecl.}
): bool =
  if conn.sctpSocket.usrsctp_set_non_blocking(1) != 0:
    warn "usrsctp_set_non_blocking fails", error = sctpStrerror()
    return false

  if conn.sctpSocket.usrsctp_set_upcall(callback, cast[pointer](conn)) != 0:
    warn "usrsctp_set_upcall fails", error = sctpStrerror()
    return false

  var nodelay: uint32 = 1
  if conn.sctpSocket.usrsctp_setsockopt(IPPROTO_SCTP, SCTP_NODELAY, addr nodelay, sizeof(nodelay).SockLen) != 0:
    warn "usrsctp_setsockopt nodelay fails", error = sctpStrerror()
    return false

  var recvinfo: uint32 = 1
  if conn.sctpSocket.usrsctp_setsockopt(IPPROTO_SCTP, SCTP_RECVRCVINFO, addr recvinfo, sizeof(recvinfo).SockLen) != 0:
    warn "usrsctp_setsockopt recvinfo fails", error = sctpStrerror()
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
    conn.acceptEvent.clear()
    await conn.acceptEvent.wait()
    if conn.state == SctpState.SctpConnected and conn.socketSetup(recvCallback):
      break
    await conn.close()

  self.connections[conn.remoteAddress()] = conn
  trackCounter(SctpConnTracker)
  return conn

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

  await conn.connect(sctpPort)

  conn.connectEvent.clear()
  await conn.connectEvent.wait()
  if conn.state == SctpState.SctpClosed:
    raise newException(WebRtcError, "SCTP - Connection failed")
  self.connections[raddr] = conn
  trackCounter(SctpConnTracker)
  return conn
