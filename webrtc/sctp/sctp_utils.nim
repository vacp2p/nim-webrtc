# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import nativesockets
import binary_serialization, chronos

var errno* {.importc, header: "<errno.h>".}: cint ## error variable

when defined(windows):
  import winlean
  const
    SctpAF_INET* = winlean.AF_INET
    SctpEINPROGRESS* = winlean.WSAEINPROGRESS.cint
else:
  const
    SctpAF_INET* = nativesockets.AF_INET
    SctpEINPROGRESS* = chronos.EINPROGRESS.cint

type
  # These three objects are used for debugging/trace only
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
  # Only used for debugging/trace
  if data.len() < 8:
    return $data
  result = "@["
  result &= $data[0] & ", " & $data[1] & ", " & $data[2] & ", " & $data[3] & " ... "
  result &= $data[^4] & ", " & $data[^3] & ", " & $data[^2] & ", " & $data[^1] & "]"

proc `$`*(packet: SctpPacketStructure): string =
  # Only used for debugging/trace
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
  # Only used for debugging/trace
  result.header = Binary.decode(buffer, SctpPacketHeader)
  var size = sizeof(SctpPacketHeader)
  while size < buffer.len:
    let chunk = Binary.decode(buffer[size ..^ 1], SctpChunk)
    result.chunks.add(chunk)
    size.inc(chunk.length.int)
    while size mod 4 != 0:
      # padding; could use `size.inc(-size %% 4)` instead but it lacks clarity
      size.inc(1)

proc sctpStrerror*(): string =
  proc strerror(
    error: int
  ): cstring {.importc: "strerror", cdecl, header: "<string.h>".}
  return $(sctpStrerror(errno))
