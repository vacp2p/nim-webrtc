# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import posix
import chronos, chronicles, stew/[endians2, byteutils]
import usrsctp
import ./sctp_utils
import ../errors
import ../dtls/dtls_connection

logScope:
  topics = "webrtc sctp_connection"

proc sctpStrerror(error: int): cstring {.importc: "strerror", cdecl, header: "<string.h>".}

type
  SctpState* = enum
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
    info*: sctp_recvv_rn
    params*: SctpMessageParameters

  SctpConn* = ref object
    conn*: DtlsConn
    state*: SctpState
    connectEvent*: AsyncEvent
    acceptEvent*: AsyncEvent
    readLoop*: Future[void]
    address*: TransportAddress
    sctpSocket*: ptr socket
    dataRecv*: AsyncQueue[SctpMessage]
    sentFuture*: Future[void]

proc new*(T: typedesc[SctpConn], conn: DtlsConn): T =
  T(conn: conn,
    state: Connecting,
    connectEvent: AsyncEvent(),
    acceptEvent: AsyncEvent(),
    dataRecv: newAsyncQueue[SctpMessage]()
   )

proc read*(self: SctpConn): Future[SctpMessage] {.async.} =
  # Used by DataChannel, returns SctpMessage in order to get the stream
  # and protocol ids
  return await self.dataRecv.popFirst()

proc toFlags(params: SctpMessageParameters): uint16 =
  if params.endOfRecord:
    result = result or SCTP_EOR
  if params.unordered:
    result = result or SCTP_UNORDERED

proc write*(self: SctpConn, buf: seq[byte],
    sendParams = default(SctpMessageParameters)) {.async.} =
  # Used by DataChannel, writes buf on the Dtls connection.
  trace "Write", buf

  var cpy = buf
  let sendvErr =
    if sendParams == default(SctpMessageParameters):
      # If writes is called by DataChannel, sendParams should never
      # be the default value. This split is useful for testing.
      self.usrsctpAwait:
        self.sctpSocket.usrsctp_sendv(cast[pointer](addr cpy[0]), cpy.len().uint, nil, 0,
                                      nil, 0, SCTP_SENDV_NOINFO.cuint, 0)
    else:
      var sendInfo = sctp_sndinfo(
        snd_sid: sendParams.streamId,
        snd_ppid: sendParams.protocolId.swapBytes(),
        snd_flags: sendParams.toFlags)
      self.usrsctpAwait:
        self.sctpSocket.usrsctp_sendv(cast[pointer](addr cpy[0]), cpy.len().uint, nil, 0,
                                      cast[pointer](addr sendInfo), sizeof(sendInfo).SockLen,
                                      SCTP_SENDV_SNDINFO.cuint, 0)
  if sendvErr < 0:
    raise newException(WebRtcError, $(sctpStrerror(sendvErr)))

proc write*(self: SctpConn, s: string) {.async.} =
  await self.write(s.toBytes())

proc close*(self: SctpConn) {.async.} =
  self.usrsctpAwait:
    self.sctpSocket.usrsctp_close()
  usrsctp_deregister_address(cast[pointer](self))
