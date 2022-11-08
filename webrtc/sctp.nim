# Nim-WebRTC
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import tables, bitops, posix
import chronos, chronicles, stew/ranges/ptr_arith
import usrsctp

export chronicles

logScope:
  topics = "webrtc sctp"

type
  SctpConnection* = ref object
    sctp: Sctp
    udp: DatagramTransport
    address: TransportAddress
    sctpSocket: ptr socket
    dataRecv: seq[byte]

  Sctp* = ref object
    udp: DatagramTransport
    connections: Table[TransportAddress, SctpConnection]
    gotConnection: AsyncEvent
    case isServer: bool
    of true:
      sock: ptr socket
    of false:
      discard
    sentFuture: Future[void]
    sentConnection: SctpConnection

const
  IPPROTO_SCTP = 132

template usrsctpAwait(sctp: Sctp, body: untyped) =
  sctp.sentFuture = nil
  body
  if sctp.sentFuture != nil:
    await sctp.sentFuture

proc perror(error: cstring) {.importc, cdecl, header: "<errno.h>".}
proc printf(format: cstring) {.cdecl, varargs.} = echo "printf"
proc packetPretty(packet: cstring): string =
  let data = $packet
  let ctn = data[23..^16]
  result = data[1..14]
  if ctn.len > 30:
    result = result & ctn[0..14] & " ... " & ctn[^14..^1]
  else:
    result = result & ctn

proc new(T: typedesc[SctpConnection],
         sctp: Sctp,
         udp: DatagramTransport,
         address: TransportAddress,
         sctpSocket: ptr socket): T =
  T(sctp: sctp, udp: udp, address: address, sctpSocket: sctpSocket)

proc read*(self: SctpConnection): Future[seq[byte]] = discard

proc write*(self: SctpConnection, buf: seq[byte]) {.async.} =
  self.sctp.sentConnection = self
  discard self.sctpSocket.usrsctp_sendv(addr buf, buf.len.uint, nil, 0, nil, 0, SCTP_SENDV_NOINFO, 0)
  await self.sctp.sentFuture

proc close*(self: SctpConnection) {.async.} = discard

proc handleUpcall(sock: ptr socket, data: pointer, flags: cint) {.cdecl.} =
  let events = usrsctp_get_events(sock)
  trace "Handle Upcall", events
  if bitor(events, SCTP_EVENT_WRITE) != 0: # and not connected:
    echo "connect"
    #connected = true
  elif bitor(events, SCTP_EVENT_READ) != 0:
    echo "recv"
  else:
    echo "/!\\ ERROR /!\\"

proc handleAccept(sock: ptr socket, data: pointer, flags: cint) {.cdecl.} =
  trace "Handle Accept"
  var
    sin: Sockaddr_in
    size: SockLen
    ipaddress: IpAddress
    port: Port
  let
    sctp: Sctp = cast[ptr Sctp](data)[]
    sctpSocket = usrsctp_accept(sctp.sock,
                            cast[ptr SockAddr](addr sin),
                            cast[ptr SockLen](addr size))
  sin.fromSockAddr(sizeof(sin).SockLen, ipaddress, port)
  let address = initTAddress(ipaddress, port)
  sctp.connections[address] = SctpConnection.new(sctp, sctp.udp, address, sctpSocket)
  sctp.gotConnection.fire()

proc getOrCreateConnection(self: Sctp,
                           udp: DatagramTransport,
                           address: TransportAddress): SctpConnection =
  if self.connections.hasKey(address):
    return self.connections[address]
  trace "Create Connection", address
  let
    sctpSocket = usrsctp_socket(AF_CONN, posix.SOCK_STREAM, IPPROTO_SCTP, nil, nil, 0, nil)
    conn = SctpConnection.new(self, udp, address, sctpSocket)
    sctpPtr = cast[pointer](addr self)
  var on: int = 1
  doAssert 0 == usrsctp_setsockopt(conn.sctpSocket,
                                   IPPROTO_SCTP,
                                   SCTP_RECVRCVINFO,
                                   addr on,
                                   sizeof(on).SockLen)
  doAssert 0 == usrsctp_set_non_blocking(conn.sctpSocket, 1)
  doAssert 0 == usrsctp_set_upcall(conn.sctpSocket, handleUpcall, nil)
  var sconn: Sockaddr_conn
  sconn.sconn_family = AF_CONN
  sconn.sconn_port = htons(5000)
  sconn.sconn_addr = sctpPtr
  self.sentConnection = conn
  echo "=======> Avant connect"
  discard conn.sctpSocket.usrsctp_connect(cast[ptr SockAddr](addr sconn), SockLen(sizeof(sconn)))
  echo "Après connect <======="
  self.connections[address] = conn
  return conn

proc sendCallback(address: pointer,
                  buffer: pointer,
                  length: uint,
                  tos: uint8,
                  set_df: uint8): cint {.cdecl.} =
  let data = usrsctp_dumppacket(buffer, length, SCTP_DUMP_OUTBOUND)
  if data != nil:
    trace "sendCallback", data = data.packetPretty(), length
    usrsctp_freedumpbuffer(data)
  let sctp: Sctp = (cast[ptr Sctp](address))[]
  proc testSend() {.async.} =
    try:
      let
        buf = @(buffer.makeOpenArray(byte, int(length)))
        address = sctp.sentConnection.address
      trace "Send To", address
      await sendTo(sctp.udp, address, buf, int(length))
    except CatchableError as exc:
      echo "Failure: ", exc.msg
  sctp.sentFuture = testSend()

proc new*(T: typedesc[Sctp], port: uint16 = 9899, isServer: bool = false): T =
  logScope: topics = "webrtc sctp"
  let
    sctp = T(gotConnection: newAsyncEvent(), isServer: isServer)
    sctpPtr = cast[pointer](addr sctp)
  proc onReceive(udp: DatagramTransport, address: TransportAddress) {.async, gcsafe.} =
    let
      msg = udp.getMessage()
      data = usrsctp_dumppacket(addr msg[0], uint(msg.len), SCTP_DUMP_INBOUND)
    if data != nil:
      trace "onReceive", data = data.packetPretty(), length = msg.len()
      usrsctp_freedumpbuffer(data)

    if sctp.isServer:
      echo "OnReceive (server): ", sctp.connections.len
      var sin: Sockaddr_in
      var slen: SockLen
      discard sctp.sock.usrsctp_accept(cast[ptr SockAddr](addr sin), addr slen)
      perror("usrsctp_accept")
      echo sin.sin_port, " ", sin.sin_addr.s_addr, " ", slen

      usrsctp_conninput(sctpPtr, addr msg[0], uint(msg.len), 0)
    else:
      echo "OnReceive (client): ", sctp.connections.len
      let conn = sctp.getOrCreateConnection(udp, address)
      sctp.sentConnection = conn
      usrsctp_conninput(sctpPtr, addr msg[0], uint(msg.len), 0)
  let
    localAddr = TransportAddress(family: AddressFamily.IPv4, port: Port(port))
  trace "local address", localAddr
  let
    udp = newDatagramTransport(onReceive, local = localAddr)
  sctp.udp = udp
  usrsctp_init_nothreads(0, sendCallback, nil)
  discard usrsctp_sysctl_set_sctp_ecn_enable(1)
  usrsctp_register_address(sctpPtr)
  if isServer:
    doAssert 0 == usrsctp_sysctl_set_sctp_blackhole(2)
    doAssert 0 == usrsctp_sysctl_set_sctp_no_csum_on_loopback(0)
    let sock = usrsctp_socket(AF_INET, posix.SOCK_STREAM, IPPROTO_SCTP, nil, nil, 0, nil)
    perror("usrsctp_socket")
    var on: int = 1
    doAssert 0 == usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_RECVRCVINFO, addr on, SockLen(sizeof(on)))
    doAssert 0 == usrsctp_set_non_blocking(sock, 1)
    doAssert 0 == sock.usrsctp_set_upcall(handleAccept, sctpPtr)
    var sconn: Sockaddr_conn
    sconn.sconn_family = AF_CONN
    sconn.sconn_port = htons(5000)
    sconn.sconn_addr = nil
    doAssert 0 == usrsctp_bind(sock, cast[ptr SockAddr](addr sconn), SockLen(sizeof(sconn)))
    doAssert 0 >= usrsctp_listen(sock, 1)
    sctp.sock = sock
  return sctp

proc listen*(self: Sctp, address: TransportAddress): Future[SctpConnection] {.async.} =
  while true:
    echo "Listening"
    if self.connections.hasKey(address):
      return self.connections[address]
    self.gotConnection.clear()
    await self.gotConnection.wait()

proc connect*(self: Sctp, address: TransportAddress): Future[SctpConnection] {.async.} =
  trace "Connect", address
  let conn = self.getOrCreateConnection(self.udp, address)
  return conn
