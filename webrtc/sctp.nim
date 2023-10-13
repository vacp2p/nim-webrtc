# Nim-WebRTC
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import tables, bitops, posix, strutils, sequtils
import chronos, chronicles, stew/[ranges/ptr_arith, byteutils]
import usrsctp
import dtls/dtls

export chronicles

logScope:
  topics = "webrtc sctp"

# TODO:
# - Replace doAssert by a proper exception management
# - Find a clean way to manage SCTP ports

type
  SctpError* = object of CatchableError

  SctpState = enum
    Connecting
    Connected
    Closed

  SctpMessageParameters* = object
    protocolId*: uint32
    streamId*: uint16
    endOfRecord*: bool
    unordered*: bool

  SctpMessage* = ref object
    data*: seq[byte]
    info: sctp_rcvinfo
    params*: SctpMessageParameters

  SctpConn* = ref object
    conn: DtlsConn
    state: SctpState
    connectEvent: AsyncEvent
    acceptEvent: AsyncEvent
    readLoop: Future[void]
    sctp: Sctp
    udp: DatagramTransport
    address: TransportAddress
    sctpSocket: ptr socket
    dataRecv: AsyncQueue[SctpMessage]

  Sctp* = ref object
    dtls: Dtls
    udp: DatagramTransport
    connections: Table[TransportAddress, SctpConn]
    gotConnection: AsyncEvent
    timersHandler: Future[void]
    isServer: bool
    sockServer: ptr socket
    pendingConnections: seq[SctpConn]
    pendingConnections2: Table[SockAddr, SctpConn]
    sentFuture: Future[void]
    sentConnection: SctpConn
    sentAddress: TransportAddress

const
  IPPROTO_SCTP = 132

proc newSctpError(msg: string): ref SctpError =
  result = newException(SctpError, msg)

template usrsctpAwait(sctp: Sctp, body: untyped): untyped =
  sctp.sentFuture = nil
  when type(body) is void:
    body
    if sctp.sentFuture != nil: await sctp.sentFuture
  else:
    let res = body
    if sctp.sentFuture != nil: await sctp.sentFuture
    res

proc perror(error: cstring) {.importc, cdecl, header: "<errno.h>".}
proc printf(format: cstring) {.cdecl, importc: "printf", varargs, header: "<stdio.h>", gcsafe.}

proc packetPretty(packet: cstring): string =
  let data = $packet
  let ctn = data[23..^16]
  result = data[1..14]
  if ctn.len > 30:
    result = result & ctn[0..14] & " ... " & ctn[^14..^1]
  else:
    result = result & ctn

proc new(T: typedesc[SctpConn],
         sctp: Sctp,
         udp: DatagramTransport,
         address: TransportAddress,
         sctpSocket: ptr socket): T =
  T(sctp: sctp,
    state: Connecting,
    udp: udp,
    address: address,
    sctpSocket: sctpSocket,
    connectEvent: AsyncEvent(),
    #TODO add some limit for backpressure?
    dataRecv: newAsyncQueue[SctpMessage]()
  )

proc new(T: typedesc[SctpConn], conn: DtlsConn): T =
  T(conn: conn,
    state: Connecting,
    connectEvent: AsyncEvent(),
    acceptEvent: AsyncEvent(),
    dataRecv: newAsyncQueue[SctpMessage]() #TODO add some limit for backpressure?
   )

proc read*(self: SctpConn): Future[SctpMessage] {.async.} =
  return await self.dataRecv.popFirst()

proc toFlags(params: SctpMessageParameters): uint16 =
  if params.endOfRecord:
    result = result or SCTP_EOR
  if params.unordered:
    result = result or SCTP_UNORDERED

proc write*(
    self: SctpConn,
    buf: seq[byte],
    sendParams = default(SctpMessageParameters),
    ) {.async.} =
  trace "Write", buf
  self.sctp.sentConnection = self
  self.sctp.sentAddress = self.address

  let
    (sendInfo, infoType) =
      if sendParams != default(SctpMessageParameters):
        (sctp_sndinfo(
          snd_sid: sendParams.streamId,
          #TODO endianness?
          snd_ppid: sendParams.protocolId,
          snd_flags: sendParams.toFlags
        ), cuint(SCTP_SENDV_SNDINFO))
      else:
        (default(sctp_sndinfo), cuint(SCTP_SENDV_NOINFO))
    sendvErr = self.sctp.usrsctpAwait:
      self.sctpSocket.usrsctp_sendv(unsafeAddr buf[0], buf.len.uint,
                                    nil, 0, unsafeAddr sendInfo, sizeof(sendInfo).SockLen,
                                    infoType, 0)

proc write*(self: SctpConn, s: string) {.async.} =
  await self.write(s.toBytes())

proc close*(self: SctpConn) {.async.} =
  self.sctp.usrsctpAwait: self.sctpSocket.usrsctp_close()

proc handleUpcall(sock: ptr socket, data: pointer, flags: cint) {.cdecl.} =
  let
    events = usrsctp_get_events(sock)
    conn = cast[SctpConn](data)
  trace "Handle Upcall", events
  if conn.state == Connecting:
    if bitand(events, SCTP_EVENT_ERROR) != 0:
      warn "Cannot connect", address = conn.address
      conn.state = Closed
    elif bitand(events, SCTP_EVENT_WRITE) != 0:
      conn.state = Connected
    conn.connectEvent.fire()
  elif bitand(events, SCTP_EVENT_READ) != 0:
    var
      message = SctpMessage(
        data: newSeq[byte](4096)
      )
      address: Sockaddr_storage
      rn: sctp_recvv_rn
      addressLen = sizeof(Sockaddr_storage).SockLen
      rnLen = sizeof(message.info).SockLen
      infotype: uint
      flags: int
    let n = sock.usrsctp_recvv(cast[pointer](addr message.data[0]), message.data.len.uint,
                               cast[ptr SockAddr](addr address),
                               cast[ptr SockLen](addr addressLen),
                               cast[pointer](addr message.info),
                               cast[ptr SockLen](addr rnLen),
                               cast[ptr cuint](addr infotype),
                               cast[ptr cint](addr flags))
    if n < 0:
      perror("usrsctp_recvv")
      return
    elif n > 0:
      if infotype == SCTP_RECVV_RCVINFO:
        message.params = SctpMessageParameters(
          #TODO endianness?
          protocolId: message.info.rcv_ppid,
          streamId: message.info.rcv_sid
        )
      if bitand(flags, MSG_NOTIFICATION) != 0:
        trace "Notification received", length = n
      else:
        try:
          conn.dataRecv.addLastNoWait(message)
        except AsyncQueueFullError:
          trace "Queue full, dropping packet"
  else:
    warn "Handle Upcall unexpected event", events

proc handleAccept(sock: ptr socket, data: pointer, flags: cint) {.cdecl.} =
  trace "Handle Accept"
  var
    sconn: Sockaddr_conn
    slen: Socklen = sizeof(Sockaddr_conn).uint32
  let
    sctp = cast[Sctp](data)
    sctpSocket = usrsctp_accept(sctp.sockServer, cast[ptr SockAddr](addr sconn), addr slen)

  # echo cast[uint64](sconn.sconn_addr)
  doAssert 0 == sctpSocket.usrsctp_set_non_blocking(1)
  let conn = cast[SctpConn](sconn.sconn_addr)
  conn.state = Connected
  conn.acceptEvent.fire()

proc getOrCreateConnection(self: Sctp,
                           udp: DatagramTransport,
                           address: TransportAddress,
                           sctpPort: uint16 = 5000): Future[SctpConn] {.async.} =
                           #TODO remove the = 5000
  if self.connections.hasKey(address):
    return self.connections[address]
  trace "Create Connection", address
  let
    sctpSocket = usrsctp_socket(AF_CONN, posix.SOCK_STREAM, IPPROTO_SCTP, nil, nil, 0, nil)
    conn = SctpConn.new(self, udp, address, sctpSocket)
  var on: int = 1
  doAssert 0 == conn.sctpSocket.usrsctp_setsockopt(IPPROTO_SCTP,
                                                   SCTP_RECVRCVINFO,
                                                   addr on,
                                                   sizeof(on).SockLen)
  doAssert 0 == usrsctp_set_non_blocking(conn.sctpSocket, 1)
  doAssert 0 == usrsctp_set_upcall(conn.sctpSocket, handleUpcall, cast[pointer](conn))
  var sconn: Sockaddr_conn
  sconn.sconn_family = AF_CONN
  sconn.sconn_port = htons(sctpPort)
  sconn.sconn_addr = cast[pointer](self)
  self.sentConnection = conn
  self.sentAddress = address
  let connErr = self.usrsctpAwait:
    conn.sctpSocket.usrsctp_connect(cast[ptr SockAddr](addr sconn), SockLen(sizeof(sconn)))
  doAssert 0 == connErr or errno == posix.EINPROGRESS, ($errno)
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
  let sctp = cast[Sctp](address)
  proc testSend() {.async.} =
    try:
      let
        buf = @(buffer.makeOpenArray(byte, int(length)))
        address = sctp.sentAddress
      trace "Send To", address
      await sendTo(sctp.udp, address, buf, int(length))
    except CatchableError as exc:
      trace "Send Failed", message = exc.msg
  sctp.sentFuture = testSend()

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

proc new*(T: typedesc[Sctp], dtls: Dtls, laddr: TransportAddress): T =
  let sctp = T(gotConnection: newAsyncEvent(),
               timersHandler: timersHandler(),
               dtls: dtls)

  usrsctp_init_nothreads(laddr.port.uint16, sendCallback, printf)
  discard usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_NONE)
  discard usrsctp_sysctl_set_sctp_ecn_enable(1)
  usrsctp_register_address(cast[pointer](sctp))
  return sctp

proc new*(T: typedesc[Sctp], port: uint16 = 9899): T =
  logScope: topics = "webrtc sctp"
  let sctp = T(gotConnection: newAsyncEvent())
  proc onReceive(udp: DatagramTransport, raddr: TransportAddress) {.async, gcsafe.} =
    let
      msg = udp.getMessage()
      data = usrsctp_dumppacket(unsafeAddr msg[0], uint(msg.len), SCTP_DUMP_INBOUND)
    if data != nil:
      if sctp.isServer:
        trace "onReceive (server)", data = data.packetPretty(), length = msg.len(), raddr
      else:
        trace "onReceive (client)", data = data.packetPretty(), length = msg.len(), raddr
      usrsctp_freedumpbuffer(data)

    if sctp.isServer:
      sctp.sentAddress = raddr
      usrsctp_conninput(cast[pointer](sctp), unsafeAddr msg[0], uint(msg.len), 0)
    else:
      let conn = await sctp.getOrCreateConnection(udp, raddr)
      sctp.sentConnection = conn
      sctp.sentAddress = raddr
      usrsctp_conninput(cast[pointer](sctp), unsafeAddr msg[0], uint(msg.len), 0)
  let
    localAddr = TransportAddress(family: AddressFamily.IPv4, port: Port(port))
    laddr = initTAddress("127.0.0.1:" & $port)
    udp = newDatagramTransport(onReceive, local = laddr)
  trace "local address", localAddr, laddr
  sctp.udp = udp
  sctp.timersHandler = timersHandler()

  usrsctp_init_nothreads(port, sendCallback, printf)
  discard usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_NONE)
  discard usrsctp_sysctl_set_sctp_ecn_enable(1)
  usrsctp_register_address(cast[pointer](sctp))

  return sctp

proc stop*(self: Sctp) {.async.} =
  discard self.usrsctpAwait usrsctp_finish()
  self.udp.close()

proc readLoopProc(res: SctpConn) {.async.} =
  while true:
    let
      msg = await res.conn.read()
      data = usrsctp_dumppacket(unsafeAddr msg[0], uint(msg.len), SCTP_DUMP_INBOUND)
    if data != nil:
      trace "Receive connection", remoteAddress = result.conn.raddr, data = data.packetPretty()
      usrsctp_freedumpbuffer(data)
    usrsctp_conninput(cast[pointer](res), unsafeAddr msg[0], uint(msg.len), 0)

proc accept*(self: Sctp): Future[SctpConn] {.async.} =
  if not self.isServer:
    raise newSctpError("Not a server")
  let conn = await self.dtls.accept()
  var res = SctpConn.new(conn)
  res.conn = await self.dtls.accept()
  let
    msg = await res.conn.read()
    data = usrsctp_dumppacket(unsafeAddr msg[0], uint(msg.len), SCTP_DUMP_INBOUND)
  if data != nil:
    trace "Receive connection", remoteAddress = res.conn.raddr, data = data.packetPretty()
    usrsctp_freedumpbuffer(data)
  # sctp.sentAddress = raddr
  usrsctp_register_address(cast[pointer](res))
  res.readLoop = res.readLoopProc()
  res.acceptEvent.clear()
  await res.acceptEvent.wait()
  return res

proc listen*(self: Sctp, sctpPort: uint16 = 5000) {.async.} =
  if self.isServer:
    trace "Try to start the server twice"
    return
  self.isServer = true
  trace "Listening", sctpPort
  doAssert 0 == usrsctp_sysctl_set_sctp_blackhole(2)
  doAssert 0 == usrsctp_sysctl_set_sctp_no_csum_on_loopback(0)
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
  discard

# proc connect*(self: Sctp,
#               address: TransportAddress,
#               sctpPort: uint16 = 5000): Future[SctpConn] {.async.} =
#   trace "Connect", address, sctpPort
#   let conn = await self.getOrCreateConnection(self.udp, address, sctpPort)
#   if conn.state == Connected:
#     return conn
#   try:
#     await conn.connectEvent.wait() # TODO: clear?
#   except CancelledError as exc:
#     conn.sctpSocket.usrsctp_close()
#     return nil
#   if conn.state != Connected:
#     raise newSctpError("Cannot connect to " & $address)
#   return conn
