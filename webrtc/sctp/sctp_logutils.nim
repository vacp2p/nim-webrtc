# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import binary_serialization

# This file defines custom objects and procedures to improve the
# readability and accuracy of logging SCTP messages. The default
# usrsctp logger may not provide sufficient detail or clarity for
# SCTP message analysis, so this implementation creates more structured
# and informative logs. By parsing and formatting SCTP packet headers
# and chunks into human-readable strings, it provides clearer insights
# into the data being transmitted. This aids debugging by offering a
# more descriptive view of SCTP traffic than what is available
# by default.

type
  SctpChunk* = object
    chunkType*: uint8
    flag*: uint8
    length* {.bin_value: it.data.len() + 4.}: uint16
    data* {.bin_len: it.length - 4.}: seq[byte]

  SctpPacketHeader* = object
    srcPort*: uint16
    dstPort*: uint16
    verifTag*: uint32
    checksum*: uint32

  SctpPacketStructure* = object
    header*: SctpPacketHeader
    chunks*: seq[SctpChunk]

proc dataToString(data: seq[byte]): string =
  if data.len() < 8:
    return $data
  result = "@["
  result &= $data[0] & ", " & $data[1] & ", " & $data[2] & ", " & $data[3] & " ... "
  result &= $data[^4] & ", " & $data[^3] & ", " & $data[^2] & ", " & $data[^1] & "]"

proc `$`*(packet: SctpPacketStructure): string =
  result = "{header: {srcPort: "
  result &= $(packet.header.srcPort) & ", dstPort: "
  result &= $(packet.header.dstPort) & "}, chunks: @["
  var counter = 0
  for chunk in packet.chunks:
    result &= "{type: " & $(chunk.chunkType) & ", len: "
    result &= $(chunk.length) & ", data: "
    result &= chunk.data.dataToString()
    counter += 1
    if counter < packet.chunks.len():
      result &= ", "
  result &= "]}"

proc getSctpPacket*(buffer: seq[byte]): SctpPacketStructure =
  result.header = Binary.decode(buffer, SctpPacketHeader)
  var size = sizeof(SctpPacketHeader)
  while size < buffer.len:
    let chunk = Binary.decode(buffer[size ..^ 1], SctpChunk)
    result.chunks.add(chunk)
    size.inc(chunk.length.int)
    while size mod 4 != 0:
      # padding; could use `size.inc(-size %% 4)` instead but it lacks clarity
      size.inc(1)
