# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import tables
import chronos, chronicles, binary_serialization
import errors, sctp/[sctp_transport, sctp_connection]

export binary_serialization

logScope:
  topics = "webrtc datachannel"

# Implementation of the DataChannel protocol, mostly following
# https://www.rfc-editor.org/rfc/rfc8831.html and
# https://www.rfc-editor.org/rfc/rfc8832.html

# -- Open/Ack DataChannel Message --
# Use binary-serialization in order to encode/decode

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
    else:
      discard

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

# -- DataChannelStream --

type
  #TODO handle closing
  DataChannelStream* = ref object
    id: uint16
    conn: SctpConn
    reliability: DataChannelType
    reliabilityParameter: uint32
    receivedData: AsyncQueue[seq[byte]]
    acked: bool

  #TODO handle closing
  DataChannelConnection* = ref object
    readLoopFut: Future[void]
    streams: Table[uint16, DataChannelStream]
    streamId: uint16
    conn*: SctpConn
    incomingStreams: AsyncQueue[DataChannelStream]

proc read*(
    stream: DataChannelStream
): Future[seq[byte]] {.async: (raises: [CancelledError]).} =
  let x = await stream.receivedData.popFirst()
  trace "read", length = x.len(), id = stream.id
  return x

proc write*(
    stream: DataChannelStream, buf: seq[byte]
) {.async: (raises: [CancelledError, WebRtcError]).} =
  trace "write", length = buf.len(), id = stream.id
  var sendInfo = SctpMessageParameters(
    streamId: stream.id, endOfRecord: true, protocolId: uint32(WebRtcBinary)
  )

  if stream.acked:
    sendInfo.unordered = not stream.reliability.ordered
    #TODO add reliability params

  if buf.len == 0:
    trace "Datachannel write empty"
    sendInfo.protocolId = uint32(WebRtcBinaryEmpty)
    await stream.conn.write(@[0'u8], sendInfo)
  else:
    await stream.conn.write(buf, sendInfo)

proc sendControlMessage(
    stream: DataChannelStream, msg: DataChannelMessage
) {.async: (raises: [CancelledError, WebRtcError]).} =
  let
    encoded = Binary.encode(msg)
    sendInfo = SctpMessageParameters(
      streamId: stream.id, endOfRecord: true, protocolId: uint32(WebRtcDcep)
    )
  trace "send control message", msg

  await stream.conn.write(encoded, sendInfo)

proc closeStream*(stream: DataChannelStream) =
  stream.conn.closeChannel(stream.id)

proc openStream*(
    conn: DataChannelConnection,
    noiseHandshake: bool,
    reliability = Reliable,
    reliabilityParameter: uint32 = 0,
): Future[DataChannelStream] {.async: (raises: [CancelledError, WebRtcError]).} =
  let streamId: uint16 =
    if not noiseHandshake:
      let res = conn.streamId
      conn.streamId += 2
      res
    else:
      0

  trace "open stream", streamId
  if reliability in [Reliable, ReliableUnordered] and reliabilityParameter != 0:
    raise newException(WebRtcError, "DataChannel - openStream: reliability parameter should be 0")

  if streamId in conn.streams:
    raise newException(WebRtcError, "DataChannel - openStream: streamId already used")

  var stream = DataChannelStream(
    id: streamId,
    conn: conn.conn,
    reliability: reliability,
    reliabilityParameter: reliabilityParameter,
    receivedData: newAsyncQueue[seq[byte]](),
  )

  conn.streams[streamId] = stream

  let msg = DataChannelMessage(
    messageType: Open,
    openMessage: DataChannelOpenMessage(
      channelType: reliability, reliabilityParameter: reliabilityParameter
    ),
  )
  await stream.sendControlMessage(msg)
  return stream

proc handleData(
    conn: DataChannelConnection, msg: SctpMessage
) {.async: (raises: [CancelledError, WebRtcError]).} =
  let streamId = msg.params.streamId
  trace "handle data message", streamId, ppid = msg.params.protocolId, data = msg.data

  conn.streams.withValue(streamId, stream):
    #TODO handle string vs binary
    if msg.params.protocolId in [uint32(WebRtcStringEmpty), uint32(WebRtcBinaryEmpty)]:
      # PPID indicate empty message
      await stream.receivedData.addLast(@[])
    else:
      await stream.receivedData.addLast(msg.data)
  do:
    raise newException(WebRtcError, "DataChannel - Got data for unknown StreamID")

proc handleControl(
    conn: DataChannelConnection, msg: SctpMessage
) {.async: (raises: [CancelledError, WebRtcError]).} =
  let decoded =
    try:
      Binary.decode(msg.data, DataChannelMessage)
    except SerializationError as exc:
      raise newException(WebRtcError, "DataChannel - " & exc.msg, exc)
  let streamId = msg.params.streamId

  trace "handle control message", decoded, streamId = msg.params.streamId
  if decoded.messageType == Ack:
    conn.streams.withValue(streamId, stream):
      if stream.acked == true:
        trace "Received ACK twice on the same StreamID", streamId
      stream.acked = true
    do:
      raise newException(WebRtcError, "DataChannel - Got ACK for unknown StreamID")
  elif decoded.messageType == Open:
    if streamId in conn.streams:
      raise newException(
        WebRtcError, "DataChannel - Got open for already existing StreamID"
      )
    let stream = DataChannelStream(
      id: streamId,
      conn: conn.conn,
      reliability: decoded.openMessage.channelType,
      reliabilityParameter: decoded.openMessage.reliabilityParameter,
      receivedData: newAsyncQueue[seq[byte]](),
    )

    conn.streams[streamId] = stream
    await conn.incomingStreams.addLast(stream)
    await stream.sendControlMessage(DataChannelMessage(messageType: Ack))

proc readLoop(conn: DataChannelConnection) {.async: (raises: [CancelledError]).} =
  try:
    while true:
      let message = await conn.conn.read()
      # TODO: check the protocolId
      if message.params.protocolId == uint32(WebRtcDcep):
        #TODO should we really await?
        await conn.handleControl(message)
      else:
        await conn.handleData(message)
  except CatchableError as exc:
    discard

proc accept*(
    conn: DataChannelConnection
): Future[DataChannelStream] {.async: (raises: [CancelledError]).} =
  return await conn.incomingStreams.popFirst()

proc new*(_: type DataChannelConnection, conn: SctpConn): DataChannelConnection =
  result = DataChannelConnection(
    conn: conn,
    incomingStreams: newAsyncQueue[DataChannelStream](),
    streamId: 1'u16, # TODO: Serveur == 1, client == 2
  )
  result.readLoopFut = result.readLoop()
