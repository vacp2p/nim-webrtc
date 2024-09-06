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

const SctpConnTracker* = "webrtc.sctp.conn"

# TODO: closing connection if usrsctp_recv / usrsctp_read fails
type
  SctpState* = enum
    SctpConnecting
    SctpConnected
    SctpClosed

  SctpMessageParameters* = object
    protocolId*: uint32
    streamId*: uint16
    endOfRecord*: bool
    unordered*: bool

  SctpMessage* = ref object
    data*: seq[byte]
    info*: sctp_recvv_rn
    params*: SctpMessageParameters

  SctpConn* = ref object
    conn*: DtlsConn
    state*: SctpState
    connectEvent*: AsyncEvent
    acceptEvent*: AsyncEvent
    readLoop*: Future[void]
    sctpSocket*: ptr socket
    dataRecv*: AsyncQueue[SctpMessage]
    sendQueue: seq[byte]

proc remoteAddress*(self: SctpConn): TransportAddress =
  if self.conn.isNil():
    raise newException(WebRtcError, "SCTP - Connection not set")
  return self.conn.remoteAddress()

proc trySend(self: SctpConn) {.async: (raises: [CancelledError]).} =
  try:
    trace "Send To", address = self.remoteAddress()
    await self.conn.write(self.sendQueue)
  except CatchableError as exc:
    trace "Send Failed", message = exc.msg

template usrsctpAwait*(self: SctpConn, body: untyped): untyped =
  # usrsctpAwait is template which set `sendQueue` to @[] then calls
  # an usrsctp function. If during the synchronous run of the usrsctp function
  # `sendQueue` is set, it is sent at the end of the function.
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
  # Callback procedure called when we receive data after
  # connection has been established.
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
      trace "usrsctp_recvv", error = sctpStrerror(n)
      # TODO: should close
      return
    elif n > 0:
      # It might be necessary to check if infotype == SCTP_RECVV_RCVINFO
      message.data.delete(n ..< message.data.len())
      trace "message info from handle upcall", msginfo = message.info
      message.params = SctpMessageParameters(
        protocolId: message.info.recvv_rcvinfo.rcv_ppid.swapBytes(),
        streamId: message.info.recvv_rcvinfo.rcv_sid,
      )
      if bitand(flags, MSG_NOTIFICATION) != 0:
        trace "Notification received", length = n
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

proc toFlags(params: SctpMessageParameters): uint16 =
  if params.endOfRecord:
    result = result or SCTP_EOR
  if params.unordered:
    result = result or SCTP_UNORDERED

proc new*(T: typedesc[SctpConn], conn: DtlsConn): T =
  T(
    conn: conn,
    state: SctpConnecting,
    connectEvent: AsyncEvent(),
    acceptEvent: AsyncEvent(),
    dataRecv: newAsyncQueue[SctpMessage](),
  )

proc read*(self: SctpConn): Future[SctpMessage] {.async: (raises: [CancelledError]).} =
  # Used by DataChannel, returns SctpMessage in order to get the stream
  # and protocol ids
  return await self.dataRecv.popFirst()

proc write*(
    self: SctpConn, buf: seq[byte], sendParams = default(SctpMessageParameters)
) {.async: (raises: [CancelledError, WebRtcError]).} =
  # Used by DataChannel, writes buf on the Dtls connection.
  trace "Write", buf

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
        snd_flags: sendParams.toFlags,
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
    raise newException(WebRtcError, "SCTP - " & $(sctpStrerror(sendvErr)))

proc write*(
    self: SctpConn, s: string
) {.async: (raises: [CancelledError, WebRtcError]).} =
  await self.write(s.toBytes())

proc close*(self: SctpConn) {.async: (raises: [CancelledError, WebRtcError]).} =
  self.usrsctpAwait:
    self.sctpSocket.usrsctp_close()
  await self.conn.close()
  usrsctp_deregister_address(cast[pointer](self))
  untrackCounter(SctpConnTracker)
