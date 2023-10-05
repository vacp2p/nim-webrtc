# Nim-WebRTC
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import chronos,
       chronicles,
       binary_serialization

export binary_serialization

logScope:
  topics = "webrtc datachannel"

type
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
