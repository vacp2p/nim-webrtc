# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import bitops
import chronos,
       bearssl,
       chronicles,
       binary_serialization
import stun_attributes, ../errors

export binary_serialization

logScope:
  topics = "webrtc stun"

const
  StunMsgHeaderSize = 20
  StunMagicCookieSeq = @[ 0x21'u8, 0x12, 0xa4, 0x42 ]
  StunMagicCookie = 0x2112a442

proc isStunMessage*(msg: seq[byte]): bool =
  msg.len >= StunMsgHeaderSize and
    msg[4..<8] == StunMagicCookieSeq and
    bitand(0xC0'u8, msg[0]) == 0'u8

type
#  Stun Header
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |0 0|     STUN Message Type     |         Message Length        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                         Magic Cookie                          |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# |                     Transaction ID (96 bits)                  |
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# Message type:
#   0x0001: Binding Request
#   0x0101: Binding Response
#   0x0111: Binding Error Response
#   0x0002: Shared Secret Request
#   0x0102: Shared Secret Response
#   0x0112: Shared Secret Error Response

  RawStunMessage = object
    msgType: uint16
    length* {.bin_value: it.content.len().}: uint16
    magicCookie: uint32
    transactionId: array[12, byte] # Down from 16 to 12 bytes in RFC5389
    content* {.bin_len: it.length.}: seq[byte]

  StunMessage* = object
    msgType*: uint16
    transactionId*: array[12, byte]
    attributes*: seq[RawStunAttribute]

proc getAttribute*[T](self: StunMessage, typ: typedesc[T]): Option[T] =
  let attributeTyp = attributeType(typ)
  for attr in self.attributes:
    if attr.attributeType == attributeTyp.uint16:
      return some(T.decode(attr))
  return none(T)

proc addLength(msgEncoded: var seq[byte], toAddLength: uint16) =
  # Add length to an already encoded message. It is necessary because
  # some attributes (such as Message Integrity or Fingerprint) need
  # the encoded message to be computed.
  let
    currentLength: uint16 = msgEncoded[2].uint16 * 256'u16 + msgEncoded[3].uint16
    totalLength = currentLength + toAddLength
  if totalLength < currentLength:
    raise newException(WebRtcError, "Stun - Try to encode a message larger than uint16 max")
  msgEncoded[2] = (totalLength div 256'u16).uint8
  msgEncoded[3] = (totalLength mod 256'u16).uint8

proc decode*(T: typedesc[StunMessage], msg: seq[byte]): StunMessage =
  let smi = Binary.decode(msg, RawStunMessage)
  return T(msgType: smi.msgType,
           transactionId: smi.transactionId,
           attributes: RawStunAttribute.decode(smi.content))

proc encode*(
    msg: StunMessage,
    messageIntegrityPassword: seq[byte]
  ): seq[byte] =
  const pad = @[0, 3, 2, 1]
  var smi = RawStunMessage(msgType: msg.msgType,
                           magicCookie: StunMagicCookie,
                           transactionId: msg.transactionId)
  for attr in msg.attributes:
    smi.content.add(Binary.encode(attr))
    smi.content.add(newSeq[byte](pad[smi.content.len() mod 4]))

  result = Binary.encode(smi)

  if messageIntegrityPassword != @[]:
    result.addLength(24)
    result.add(Binary.encode(MessageIntegrity.encode(result, messageIntegrityPassword)))

  result.addLength(8)
  result.add(Binary.encode(Fingerprint.encode(result)))
