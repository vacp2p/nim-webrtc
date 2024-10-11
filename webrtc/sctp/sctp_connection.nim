# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import nativesockets, bitops, sequtils
import usrsctp, chronos, chronicles, stew/[ptrops, endians2, byteutils]
import ./sctp_utils, ../errors, ../dtls/dtls_connection

logScope:
  topics = "webrtc sctp_connection"

const
  SctpConnTracker* = "webrtc.sctp.conn"
  IPPROTO_SCTP = 132 # Official IANA number

type
  SctpConnOnClose* = proc() {.raises: [], gcsafe.}

  SctpState* = enum
    SctpConnecting
    SctpConnected
    SctpClosed

  SctpMessageParameters* = object
    # This object is used to help manage messages exchanged over SCTP
    # within the DataChannel stack.
    protocolId*: uint32
    # protocolId is used to distinguish different protocols within
    # SCTP stream. In WebRTC, this is used to define the type of application
    # data being transferred (text data, binary data...).
    streamId*: uint16
    # streamId identifies the specific SCTP stream. In WebRTC, each
    # DataChannel corresponds to a different stream, so the streamId is
    # used to map the message to the appropriate DataChannel.
    endOfRecord*: bool
    # endOfRecord indicates whether the current SCTP message is the
    # final part of a record or not. This is related to the
    # fragmentation and reassembly of messages.
    unordered*: bool
    # The unordered flag determines whether the message should be
    # delivered in order or not. SCTP allows for both ordered and
    # unordered delivery of messages.

  SctpMessage* = ref object
    data*: seq[byte]
    info*: sctp_recvv_rn
    params*: SctpMessageParameters

  SctpConn* = ref object
    conn: DtlsConn # Underlying DTLS Connection
    sctpSocket*: ptr socket # Current usrsctp socket

    state*: SctpState # Current Sctp State
    onClose: seq[SctpConnOnClose] # List of procedure to run while closing a connection

    connectEvent*: AsyncEvent # Event fired when the connection is connected
    acceptEvent*: AsyncEvent # Event fired when the connection is accepted

    # Infinite loop reading on the underlying DTLS Connection.
    readLoop: Future[void].Raising([CancelledError, WebRtcError])

    dataRecv: AsyncQueue[SctpMessage] # Queue of messages to be read
    sendQueue: seq[byte] # Queue of messages to be sent

proc remoteAddress*(self: SctpConn): TransportAddress =
  if self.conn.isNil():
    raise newException(WebRtcError, "SCTP - Connection not set")
  return self.conn.remoteAddress()

template usrsctpAwait(self: SctpConn, body: untyped): untyped =
  # usrsctpAwait is template which set `sendQueue` to @[] then calls
  # an usrsctp function. If during the synchronous run of the usrsctp function
  # `sendQueue` is set, it is sent at the end of the function.
  proc trySend(conn: SctpConn) {.async: (raises: [CancelledError]).} =
    try:
      trace "Send To", address = conn.remoteAddress()
      await conn.conn.write(self.sendQueue)
    except CatchableError as exc:
      trace "Send Failed", exceptionMsg = exc.msg

  self.sendQueue = @[]
  when type(body) is void:
    (body)
    if self.sendQueue.len() > 0:
      await self.trySend()
  else:
    let res = (body)
    if self.sendQueue.len() > 0:
      await self.trySend()
    res

# -- usrsctp send and receive callback --

proc recvCallback*(sock: ptr socket, data: pointer, flags: cint) {.cdecl.} =
  # Callback procedure called when we receive data after a connection
  # has been established.
  let
    conn = cast[SctpConn](data)
    events = usrsctp_get_events(sock)

  trace "Receive callback", events
  if bitand(events, SCTP_EVENT_READ) != 0:
    var
      message = SctpMessage(data: newSeq[byte](4096))
      address: Sockaddr_storage
      rn: sctp_recvv_rn
      addressLen = sizeof(Sockaddr_storage).SockLen
      rnLen = sizeof(sctp_recvv_rn).SockLen
      infotype: uint
      flags: int
    let n = sock.usrsctp_recvv(
      cast[pointer](addr message.data[0]),
      message.data.len.uint,
      cast[ptr SockAddr](addr address),
      cast[ptr SockLen](addr addressLen),
      cast[pointer](addr message.info),
      cast[ptr SockLen](addr rnLen),
      cast[ptr cuint](addr infotype),
      cast[ptr cint](addr flags),
    )
    if n < 0:
      warn "usrsctp_recvv", error = sctpStrerror()
      return
    elif n > 0:
      message.data.delete(n ..< message.data.len())
      trace "message info from handle upcall", msginfo = message.info
      message.params = SctpMessageParameters(
        protocolId: message.info.recvv_rcvinfo.rcv_ppid.swapBytes(),
        streamId: message.info.recvv_rcvinfo.rcv_sid,
      )
      if bitand(flags, MSG_NOTIFICATION) != 0:
        let notif = cast[ptr sctp_notification](data)
        trace "Notification received", notifType = notif.sn_header.sn_type
      else:
        try:
          conn.dataRecv.addLastNoWait(message)
        except AsyncQueueFullError:
          trace "Queue full, dropping packet"
  elif bitand(events, SCTP_EVENT_WRITE) != 0:
    trace "sctp event write in the upcall"
  else:
    warn "Handle Upcall unexpected event", events

proc sendCallback*(
    ctx: pointer, buffer: pointer, length: uint, tos: uint8, set_df: uint8
): cint {.cdecl.} =
  # This proc is called by usrsctp everytime usrsctp tries to send data.
  let
    conn = cast[SctpConn](ctx)
    buf = @(buffer.makeOpenArray(byte, int(length)))
  trace "sendCallback", sctpPacket = $(buf.getSctpPacket())
  proc testSend() {.async: (raises: [CancelledError]).} =
    try:
      trace "Send To", address = conn.remoteAddress()
      await conn.conn.write(buf)
    except CatchableError as exc:
      trace "Send Failed", message = exc.msg

  conn.sendQueue = buf

proc addOnClose*(self: SctpConn, onCloseProc: SctpConnOnClose) =
  ## Adds a proc to be called when SctpConn is closed
  ##
  self.onClose.add(onCloseProc)

proc readLoopProc(self: SctpConn) {.async: (raises: [CancelledError, WebRtcError]).} =
  while true:
    var msg = await self.conn.read()
    if msg == @[]:
      trace "Sctp read loop stopped, DTLS connection closed"
      return
    trace "Receive data",
      remoteAddress = self.conn.remoteAddress(), sctPacket = $(msg.getSctpPacket())
    self.usrsctpAwait:
      usrsctp_conninput(cast[pointer](self), addr msg[0], uint(msg.len), 0)

proc new*(T: typedesc[SctpConn], conn: DtlsConn): T =
  result = T(
    conn: conn,
    state: SctpConnecting,
    connectEvent: AsyncEvent(),
    acceptEvent: AsyncEvent(),
    dataRecv: newAsyncQueue[SctpMessage](),
  )
  result.readLoop = result.readLoopProc()
  usrsctp_register_address(cast[pointer](result))

proc connect*(self: SctpConn, sctpPort: uint16) {.async: (raises: [CancelledError, WebRtcError]).} =
  var sconn: Sockaddr_conn
  when compiles(sconn.sconn_len):
    sconn.sconn_len = sizeof(sconn).uint8
  sconn.sconn_family = AF_CONN
  sconn.sconn_port = htons(sctpPort)
  sconn.sconn_addr = cast[pointer](self)
  let connErr = self.usrsctpAwait: self.sctpSocket.usrsctp_connect(
    cast[ptr SockAddr](addr sconn), SockLen(sizeof(sconn))
  )
  if connErr != 0 and errno != SctpEINPROGRESS:
    raise
      newException(WebRtcError, "SCTP - Connection failed: " & sctpStrerror())

proc read*(self: SctpConn): Future[SctpMessage] {.async: (raises: [CancelledError, WebRtcError]).} =
  # Used by DataChannel, returns SctpMessage in order to get the stream
  # and protocol ids
  if self.state == SctpClosed:
    raise newException(WebRtcError, "Try to read on an already closed SctpConn")
  return await self.dataRecv.popFirst()

proc toFlags(params: SctpMessageParameters): uint16 =
  if params.endOfRecord:
    result = result or SCTP_EOR
  if params.unordered:
    result = result or SCTP_UNORDERED

proc write*(
    self: SctpConn, buf: seq[byte], sendParams = default(SctpMessageParameters)
) {.async: (raises: [CancelledError, WebRtcError]).} =
  # Used by DataChannel, writes buf on the Dtls connection.
  if self.state == SctpClosed:
    raise newException(WebRtcError, "Try to write on an already closed SctpConn")
  var cpy = buf
  let sendvErr =
    if sendParams == default(SctpMessageParameters):
      # If writes is called by DataChannel, sendParams should never
      # be the default value. This split is useful for testing.
      self.usrsctpAwait:
        self.sctpSocket.usrsctp_sendv(
          cast[pointer](addr cpy[0]),
          cpy.len().uint,
          nil,
          0,
          nil,
          0,
          SCTP_SENDV_NOINFO.cuint,
          0,
        )
    else:
      var sendInfo = sctp_sndinfo(
        snd_sid: sendParams.streamId,
        snd_ppid: sendParams.protocolId.swapBytes(),
        snd_flags: sendParams.toFlags(),
      )
      self.usrsctpAwait:
        self.sctpSocket.usrsctp_sendv(
          cast[pointer](addr cpy[0]),
          cpy.len().uint,
          nil,
          0,
          cast[pointer](addr sendInfo),
          sizeof(sendInfo).SockLen,
          SCTP_SENDV_SNDINFO.cuint,
          0,
        )
  if sendvErr < 0:
    raise newException(WebRtcError, "SCTP - " & sctpStrerror())

proc write*(
    self: SctpConn, s: string
) {.async: (raises: [CancelledError, WebRtcError]).} =
  await self.write(s.toBytes())

type
  # This object is a workaround, srs_stream_list in usrsctp is an
  # UncheckedArray, and they're not assignable.
  sctp_reset_streams_workaround = object
    srs_assoc_id: sctp_assoc_t
    srs_flags: uint16
    srs_number_streams: uint16
    srs_stream_list: array[1, uint16]

proc closeChannel*(self: SctpConn, streamId: uint16) =
  ## Resets a specific outgoing SCTP stream identified by
  ## streamId to close the associated DataChannel.
  var srs: sctp_reset_streams_workaround
  let len = sizeof(srs)

  srs.srs_flags = SCTP_STREAM_RESET_OUTGOING
  srs.srs_number_streams = 1
  srs.srs_stream_list[0] = streamId
  let ret = usrsctp_setsockopt(
    self.sctpSocket,
    IPPROTO_SCTP,
    SCTP_RESET_STREAMS,
    addr srs,
    len.Socklen
  )
  if ret < 0:
    raise newException(WebRtcError, "SCTP - Close channel failed: " & sctpStrerror())

proc closeAllChannels*(self: SctpConn) =
  ## Resets all outgoing SCTP streams, effectively closing all
  ## open DataChannels for the current SCTP connection.
  var srs: sctp_reset_streams_workaround
  let len = sizeof(srs) - sizeof(srs.srs_stream_list)

  srs.srs_flags = SCTP_STREAM_RESET_OUTGOING
  srs.srs_number_streams = 0 # 0 means all channels
  let ret = usrsctp_setsockopt(
    self.sctpSocket,
    IPPROTO_SCTP,
    SCTP_RESET_STREAMS,
    addr srs,
    len.Socklen
  )
  if ret < 0:
    raise newException(WebRtcError, "SCTP - Close all channels failed: " & sctpStrerror())

proc close*(self: SctpConn) {.async: (raises: [CancelledError, WebRtcError]).} =
  ## Closes the entire SCTP connection by resetting all channels,
  ## deregistering the address, stopping the read loop, and cleaning up resources.
  if self.state == SctpClosed:
    debug "Try to close SctpConn twice"
    return
  self.closeAllChannels()
  usrsctp_deregister_address(cast[pointer](self))
  self.usrsctpAwait:
    self.sctpSocket.usrsctp_close()
  await self.readLoop.cancelAndWait()
  self.state = SctpClosed
  untrackCounter(SctpConnTracker)
  await self.conn.close()
  for onCloseProc in self.onClose:
    onCloseProc()
  self.onClose = @[]
