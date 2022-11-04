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

proc perror(error: cstring) {.importc, cdecl, header: "<errno.h>".}

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
  let e = usrsctp_get_events(sock)
  echo "handleUpcall: event = ", e
  if bitor(e, SCTP_EVENT_WRITE) != 0: # and not connected:
    echo "connect"
    #connected = true
  elif bitor(e, SCTP_EVENT_READ) != 0:
    echo "recv"
  else:
    echo "/!\\ ERROR /!\\"

proc handleAccept(sock: ptr socket, data: pointer, flags: cint) {.cdecl.} =
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
  let
    sctpSocket = usrsctp_socket(AF_CONN, posix.SOCK_STREAM, IPPROTO_SCTP, nil, nil, 0, nil)
    conn = SctpConnection.new(self, udp, address, sctpSocket)
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
  sconn.sconn_addr = nil
  doAssert 0 == conn.sctpSocket.usrsctp_connect(cast[ptr SockAddr](addr sconn), SockLen(sizeof(sconn)))
  self.connections[address] = conn
  return conn

proc sendCallback(address: pointer,
                  buffer: pointer,
                  length: uint,
                  tos: uint8,
                  set_df: uint8): cint {.cdecl.} =
  trace "sendCallback", data = usrsctp_dumppacket(buffer, length, SCTP_DUMP_OUTBOUND)
  let sctp: ptr Sctp = cast[ptr Sctp](address)
  proc testSend() {.async.} =
    try:
      let buf = @(buffer.makeOpenArray(byte, int(length)))
      await sendTo(sctp[].udp, sctp.sentConnection.address, buf, int(length))
    except CatchableError as exc:
      echo "Failure: ", exc.msg
  sctp.sentFuture = testSend()

proc new*(T: typedesc[Sctp], port: uint16 = 9899, isServer: bool = false): T =
  let
    sctp = T(gotConnection: newAsyncEvent())
    sctpPtr = cast[pointer](addr sctp)
  proc onReceive(udp: DatagramTransport, address: TransportAddress) {.async.} =
    let
      msg = udp.getMessage()
      conn = sctp.getOrCreateConnection(udp, address)
      connPtr = cast[pointer](addr conn)
    usrsctp_conninput(connPtr, addr msg[0], uint(msg.len), 0)
  let
    localAddr = TransportAddress(family: AddressFamily.IPv4, port: Port(port))
    udp = newDatagramTransport(onReceive, local = localAddr)
  usrsctp_init_nothreads(port, sendCallback, nil) # TODO maybe put a debugger instead of nil
  discard usrsctp_sysctl_set_sctp_ecn_enable(1)
  usrsctp_register_address(sctpPtr)
  sctp.udp = udp
  if isServer:
    echo errno, " <="
    let sock = usrsctp_socket(AF_INET, posix.SOCK_STREAM, IPPROTO_SCTP, nil, nil, 0, nil)
    perror("usrsctp_socket")
    var on: int = 1
    echo "=> ", errno
    doAssert 0 == usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_RECVRCVINFO, addr on, SockLen(sizeof(on)))
    doAssert 0 == usrsctp_set_non_blocking(sock, 1)
    echo sock.usrsctp_set_upcall(handleAccept, sctpPtr)
    echo errno
    var sconn: Sockaddr_conn
    sconn.sconn_family = AF_CONN
    sconn.sconn_port = htons(5000)
    sconn.sconn_addr = nil
    echo usrsctp_bind(sock, cast[ptr SockAddr](addr sconn), SockLen(sizeof(sconn)))
    doAssert 0 < usrsctp_listen(sock, 1)
    sctp.sock = sock
  return sctp

proc listen*(self: Sctp, address: TransportAddress): Future[SctpConnection] {.async.} =
  while true:
    if self.connections.hasKey(address):
      return self.connections[address]
    self.gotConnection.clear()
    await self.gotConnection.wait()

proc connect*(self: Sctp, address: TransportAddress): Future[SctpConnection] {.async.} =
  let conn = self.getOrCreateConnection(self.udp, address)
  return conn
