import bitops
import chronos,
       chronicles,
       binary_serialization,
       stew/objects
import stunattributes

export binary_serialization

logScope:
  topics = "webrtc stun"

const
  msgHeaderSize = 20
  magicCookieSeq = @[ 0x21'u8, 0x12, 0xa4, 0x42 ]
  magicCookie = 0x2112a442
  BindingRequest = 0x0001'u16
  BindingResponse = 0x0101'u16

proc decode(T: typedesc[RawStunAttribute], cnt: seq[byte]): seq[RawStunAttribute] =
  const val = @[0, 3, 2, 1]
  var padding = 0
  while padding < cnt.len():
    let attr = Binary.decode(cnt[padding ..^ 1], RawStunAttribute)
    result.add(attr)
    padding += 4 + attr.value.len()
    padding += val[padding mod 4]

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
    length* {.bin_value: it.content.len() + 8.}: uint16
    magicCookie: uint32
    transactionId: array[12, byte]
    content* {.bin_len: it.length.}: seq[byte]

  StunMessage* = object
    msgType*: uint16
    transactionId*: array[12, byte]
    attributes*: seq[RawStunAttribute]

  Stun* = object

proc getAttribute(attrs: seq[RawStunAttribute], typ: uint16): Option[seq[byte]] =
  for attr in attrs:
    if attr.attributeType == typ:
      return some(attr.value)
  return none(seq[byte])

proc isMessage*(T: typedesc[Stun], msg: seq[byte]): bool =
  msg.len >= msgHeaderSize and msg[4..<8] == magicCookieSeq and bitand(0xC0'u8, msg[0]) == 0'u8

proc decode*(T: typedesc[StunMessage], msg: seq[byte]): StunMessage =
  let smi = Binary.decode(msg, RawStunMessage)
  return T(msgType: smi.msgType,
           transactionId: smi.transactionId,
           attributes: RawStunAttribute.decode(smi.content))

proc encode*(msg: StunMessage): seq[byte] =
  const val = @[0, 3, 2, 1]
  var smi = RawStunMessage(msgType: msg.msgType,
                             magicCookie: magicCookie,
                             transactionId: msg.transactionId)
  for attr in msg.attributes:
    smi.content.add(Binary.encode(attr))
    smi.content.add(newSeq[byte](val[smi.content.len() mod 4]))

  result = Binary.encode(smi)
  result.add(Binary.encode(Fingerprint.encode(result)))

proc getResponse*(T: typedesc[Stun], msg: seq[byte],
    address: TransportAddress): Option[StunMessage] =
  let sm =
    try:
      StunMessage.decode(msg)
    except CatchableError as exc:
      return none(StunMessage)

  if sm.msgType != BindingRequest:
    return none(StunMessage)

  var res = StunMessage(msgType: BindingResponse,
                        transactionId: sm.transactionId)

  var unknownAttr: seq[uint16]
  for attr in sm.attributes:
    let typ = attr.attributeType
    if typ.isRequired() and typ notin StunAttributeEnum:
      unknownAttr.add(typ)
  if unknownAttr.len() > 0:
    res.attributes.add(ErrorCode.encode(ECUnknownAttribute))
    res.attributes.add(UnknownAttribute.encode(unknownAttr))
    return some(res)

  #if sm.attributes.getAttribute())

proc new*(T: typedesc[Stun]): T =
  result = T()
