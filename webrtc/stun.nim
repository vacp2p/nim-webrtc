import bitops
import chronos, chronicles
import binary_serialization

logScope:
  topics = "webrtc stun"

const
  msgHeaderSize = 20
  magicCookieSeq = @[ 0x21'u8, 0x12, 0xa4, 0x42 ]
  magicCookie = 0x2112a442

type
# Stun Attribute
# 0                   1                   2                   3
# 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |         Type                  |            Length             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                         Value (variable)                ....
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  StunAttribute* = object 
    attributeType*: uint16
    length* {.bin_value: it.value.len.}: uint16
    value* {.bin_len: it.length.}: seq[byte]

proc decode(T: typedesc[StunAttribute], cnt: seq[byte]): seq[StunAttribute] =
  const val = @[0, 3, 2, 1]
  var padding = 0
  while padding < cnt.len():
    let attr = Binary.decode(cnt[padding ..^ 1], StunAttribute)
    result.add(attr)
    padding += 4 + attr.value.len()
    padding += val[padding mod 4]

proc seqAttrLen(s: seq[StunAttribute]): uint16 =
  for it in s:
    result = it.length + 4

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
  StunMessageInner = object
    msgType: uint16
    length* {.bin_value: it.content.len().}: uint16
    magicCookie: uint32
    transactionId: array[12, byte]
    content* {.bin_len: it.length.}: seq[byte]
  
  StunMessage* = object
    msgType*: uint16
    transactionId*: array[12, byte]
    attributes*: seq[StunAttribute]

  Stun* = object

proc isMessage*(T: typedesc[Stun], msg: seq[byte]): bool =
  msg.len >= msgHeaderSize and msg[4..<8] == magicCookie and bitand(0xC0'u8, msg[0]) == 0'u8

proc decode*(T: typedesc[StunMessage], msg: seq[byte]): StunMessage =
  let smi = Binary.decode(msg, StunMessageInner)
  return T(msgType: smi.msgType,
           transactionId: smi.transactionId,
           attributes: StunAttribute.decode(smi.content))

proc encode*(msg: StunMessage): seq[byte] =
  const val = @[0, 3, 2, 1]
  var smi = StunMessageInner(msgType: msg.msgType,
                             magicCookie: magicCookie,
                             transactionId: msg.transactionId)
  for attr in msg.attributes:
    smi.content.add(Binary.encode(attr))
    smi.content.add(newSeq[byte](val[smi.content.len() mod 4]))

  return Binary.encode(smi)

proc new*(T: typedesc[Stun]): T =
  result = T()
