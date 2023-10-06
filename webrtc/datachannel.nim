# Nim-WebRTC
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import tables

import chronos,
       chronicles,
       binary_serialization

import sctp

export binary_serialization

logScope:
  topics = "webrtc datachannel"

type
  DataChannelProtocolIds* {.size: 4.} = enum
    WebRtcDcep = 50
    WebRtcString = 51
    WebRtcBinary = 53
    WebRtcStringEmpty = 56
    WebRtcBinaryEmpty = 57

  DataChannelMessageType* {.size: 1.} = enum
    Reserved = 0x00
    Ack = 0x02
    Open = 0x03

  DataChannelMessage* = object
    case messageType*: DataChannelMessageType
    of Open: openMessage*: DataChannelOpenMessage
    else: discard

  DataChannelType {.size: 1.} = enum
    Reliable = 0x00
    PartialReliableRexmit = 0x01
    PartialReliableTimed = 0x02
    ReliableUnordered = 0x80
    PartialReliableRexmitUnordered = 0x81
    PartialReliableTimedUnorderd = 0x82

  DataChannelOpenMessage* = object
    channelType*: DataChannelType
    priority*: uint16
    reliabilityParameter*: uint32
    labelLength* {.bin_value: it.label.len.}: uint16
    protocolLength* {.bin_value: it.protocol.len.}: uint16
    label* {.bin_len: it.labelLength.}: seq[byte]
    protocol* {.bin_len: it.protocolLength.}: seq[byte]

proc ordered(t: DataChannelType): bool =
  t in [Reliable, PartialReliableRexmit, PartialReliableTimed]

type
  #TODO handle closing
  DataChannelStream* = ref object
    id: uint16
    conn: SctpConnection
    reliability: DataChannelType
    reliabilityParameter: uint32
    receivedData: AsyncQueue[seq[byte]]
    acked: bool

  #TODO handle closing
  DataChannelConnection* = ref object
    readLoopFut: Future[void]
    streams: Table[uint16, DataChannelStream]
    conn: SctpConnection
    incomingStreams: AsyncQueue[DataChannelStream]

proc read*(stream: DataChannelStream): Future[seq[byte]] {.async.} =
  return await stream.receivedData.popLast()

proc write*(stream: DataChannelStream, buf: seq[byte]) {.async.} =
  var
    sendInfo = SctpMessageParameters(
      streamId: stream.id,
      endOfRecord: true,
      protocolId: uint32(WebRtcBinary)
    )

  if stream.acked:
    sendInfo.unordered = not stream.reliability.ordered
    #TODO add reliability params

  if buf.len == 0:
    sendInfo.protocolId = uint32(WebRtcBinaryEmpty)
    await stream.conn.write(@[0'u8], sendInfo)
  else:
    await stream.conn.write(buf, sendInfo)

proc sendControlMessage(stream: DataChannelStream, msg: DataChannelMessage) {.async.} =
  let
    encoded = Binary.encode(msg)
    sendInfo = SctpMessageParameters(
      streamId: stream.id,
      endOfRecord: true,
      protocolId: uint32(WebRtcDcep)
    )

  await stream.conn.write(encoded, sendInfo)

proc openStream*(
  conn: DataChannelConnection,
  streamId: uint16,
  reliability = Reliable, reliabilityParameter: uint32 = 0): Future[DataChannelStream] {.async.} =

  if reliability in [Reliable, ReliableUnordered] and reliabilityParameter != 0:
    raise newException(ValueError, "reliabilityParameter should be 0")

  if streamId in conn.streams:
    raise newException(ValueError, "streamId already used")

  #TODO: we should request more streams when required
  # https://github.com/sctplab/usrsctp/blob/a0cbf4681474fab1e89d9e9e2d5c3694fce50359/programs/rtcweb.c#L304C16-L304C16

  var stream = DataChannelStream(
      id: streamId, conn: conn.conn,
      reliability: reliability,
      reliabilityParameter: reliabilityParameter,
      receivedData: newAsyncQueue[seq[byte]]()
  )

  conn.streams[streamId] = stream

  let
    msg = DataChannelMessage(
      messageType: Open,
      openMessage: DataChannelOpenMessage(
        channelType: reliability,
        reliabilityParameter: reliabilityParameter
      )
    )
  await stream.sendControlMessage(msg)
  return stream

proc handleData(conn: DataChannelConnection, msg: SctpMessage) =
  let streamId = msg.params.streamId

  if streamId notin conn.streams:
    raise newException(ValueError, "got data for unknown streamid")

  let stream = conn.streams[streamId]

  #TODO handle string vs binary
  if msg.params.protocolId in [uint32(WebRtcStringEmpty), uint32(WebRtcBinaryEmpty)]:
    # PPID indicate empty message
    stream.receivedData.addLastNoWait(@[])
  else:
    stream.receivedData.addLastNoWait(msg.data)

proc handleControl(conn: DataChannelConnection, msg: SctpMessage) {.async.} =
  let
    decoded = Binary.decode(msg.data, DataChannelMessage)
    streamId = msg.params.streamId

  if decoded.messageType == Ack:
    if streamId notin conn.streams:
      raise newException(ValueError, "got ack for unknown streamid")
    conn.streams[streamId].acked = true
  elif decoded.messageType == Open:
    if streamId in conn.streams:
      raise newException(ValueError, "got open for already existing streamid")

    let stream = DataChannelStream(
      id: streamId, conn: conn.conn,
      reliability: decoded.openMessage.channelType,
      reliabilityParameter: decoded.openMessage.reliabilityParameter,
      receivedData: newAsyncQueue[seq[byte]]()
    )

    conn.streams[streamId] = stream

    await stream.sendControlMessage(DataChannelMessage(messageType: Ack))

proc readLoop(conn: DataChannelConnection) {.async.} =
  try:
    while true:
      let message = await conn.conn.read()
      if message.params.protocolId == uint32(WebRtcDcep):
        #TODO should we really await?
        await conn.handleControl(message)
      else:
        conn.handleData(message)

  except CatchableError as exc:
    discard

proc accept*(conn: DataChannelConnection): Future[DataChannelStream] {.async.} =
  if isNil(conn.readLoopFut):
    conn.readLoopFut = conn.readLoop()
  return await conn.incomingStreams.popFirst()
