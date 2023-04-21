import binary_serialization,
       stew/byteutils
import utils

type
# Stun Attribute
# 0                   1                   2                   3
# 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |         Type                  |            Length             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                         Value (variable)                ....
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  RawStunAttribute* = object 
    attributeType*: uint16
    length* {.bin_value: it.value.len.}: uint16
    value* {.bin_len: it.length.}: seq[byte]

  StunAttributeEnum* = enum
    AttrMappedAddress = 0x0001
    AttrChangeRequest = 0x0003 # RFC5780 Nat Behavior Discovery
    AttrSourceAddress = 0x0004 # Deprecated
    AttrChangedAddress = 0x0005 # Deprecated
    AttrUsername = 0x0006
    AttrMessageIntegrity = 0x0008
    AttrErrorCode = 0x0009
    AttrUnknownAttributes = 0x000A
    AttrChannelNumber = 0x000C # RFC5766 TURN
    AttrLifetime = 0x000D # RFC5766 TURN
    AttrXORPeerAddress = 0x0012 # RFC5766 TURN
    AttrData = 0x0013 # RFC5766 TURN
    AttrRealm = 0x0014
    AttrNonce = 0x0015
    AttrXORRelayedAddress = 0x0016 # RFC5766 TURN
    AttrRequestedAddressFamily = 0x0017 # RFC6156
    AttrEvenPort = 0x0018 # RFC5766 TURN
    AttrRequestedTransport = 0x0019 # RFC5766 TURN
    AttrDontFragment = 0x001A # RFC5766 TURN
    AttrMessageIntegritySHA256 = 0x001C # RFC8489 STUN (v2)
    AttrPasswordAlgorithm = 0x001D # RFC8489 STUN (v2)
    AttrUserhash = 0x001E # RFC8489 STUN (v2)
    AttrXORMappedAddress = 0x0020
    AttrReservationToken = 0x0022 # RFC5766 TURN
    AttrPriority = 0x0024 # RFC5245 ICE
    AttrUseCandidate = 0x0025 # RFC5245 ICE
    AttrPadding = 0x0026 # RFC5780 Nat Behavior Discovery
    AttrResponsePort = 0x0027 # RFC5780 Nat Behavior Discovery
    AttrConnectionID = 0x002a # RFC6062 TURN Extensions
    AttrPasswordAlgorithms = 0x8002 # RFC8489 STUN (v2)
    AttrAlternateDomain = 0x8003 # RFC8489 STUN (v2)
    AttrSoftware = 0x8022
    AttrAlternateServer = 0x8023
    AttrCacheTimeout = 0x8027 # RFC5780 Nat Behavior Discovery
    AttrFingerprint = 0x8028
    AttrICEControlled = 0x8029 # RFC5245 ICE
    AttrICEControlling = 0x802A # RFC5245 ICE
    AttrResponseOrigin = 0x802b # RFC5780 Nat Behavior Discovery
    AttrOtherAddress = 0x802C # RFC5780 Nat Behavior Discovery
    AttrOrigin = 0x802F

proc isRequired*(typ: uint16): bool = typ <= 0x7FFF'u16
proc isOptional*(typ: uint16): bool = typ >= 0x8000'u16

# Error Code
type
  ErrorCodeEnum* = enum
    ECTryAlternate = 300
    ECBadRequest = 400
    ECUnauthenticated = 401
    ECUnknownAttribute = 420
    ECStaleNonce = 438
    ECServerError = 500
  ErrorCode* = object
    reserved1: uint16 # should be 0
    reserved2 {.bin_bitsize: 5.}: uint8 # should be 0
    class {.bin_bitsize: 3.}: uint8
    number: uint8
    reason: seq[byte]

proc encode*(T: typedesc[ErrorCode], code: ErrorCodeEnum, reason: string = ""): RawStunAttribute =
  let
    ec = T(class: (code.uint16 div 100'u16).uint8,
                   number: (code.uint16 mod 100'u16).uint8,
                   reason: reason.toBytes())
    value = Binary.encode(ec)
  result = RawStunAttribute(attributeType: AttrErrorCode.uint16,
                            length: value.len().uint16,
                            value: value)

# Unknown Attribute
type
  UnknownAttribute* = object
    unknownAttr: seq[uint16]

proc encode*(T: typedesc[UnknownAttribute], unknownAttr: seq[uint16]): RawStunAttribute =
  let
    ua = T(unknownAttr: unknownAttr)
    value = Binary.encode(ua)
  result = RawStunAttribute(attributeType: AttrUnknownAttributes.uint16,
                            length: value.len().uint16,
                            value: value)

type
  Fingerprint* = object
    crc32: uint32

proc encode*(T: typedesc[Fingerprint], msg: seq[byte]): RawStunAttribute =
  let value = Binary.encode(Fingerprint(crc32: crc32(msg) xor 0x5354554e'u32))
  result = RawStunAttribute(attributeType: AttrFingerprint.uint16,
                            length: value.len().uint16,
                            value: value)
