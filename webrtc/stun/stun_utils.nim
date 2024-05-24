# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import sequtils, typetraits, std/sha1
import bearssl

proc generateRandomSeq*(rng: ref HmacDrbgContext, size: int): seq[byte] =
  result = newSeq[byte](size)
  rng[].generate(result)

proc createCrc32Table(): array[0..255, uint32] =
  for i in 0..255:
    var rem = i.uint32
    for j in 0..7:
      if (rem and 1) > 0:
        rem = (rem shr 1) xor 0xedb88320'u32
      else:
        rem = rem shr 1
    result[i] = rem

proc crc32*(s: seq[byte]): uint32 =
  # CRC-32 is used for the fingerprint attribute
  # See https://datatracker.ietf.org/doc/html/rfc5389#section-15.5
  const crc32table = createCrc32Table()
  result = 0xffffffff'u32
  for c in s:
    result = (result shr 8) xor crc32table[(result and 0xff) xor c]
  result = not result

proc hmacSha1*(key: seq[byte], msg: seq[byte]): seq[byte] =
  # HMAC-SHA1 is used for the message integrity attribute
  # See https://datatracker.ietf.org/doc/html/rfc5389#section-15.4
  let
    keyPadded =
      if len(key) > 64:
        @(secureHash(key.mapIt(it.chr)).distinctBase)
      elif key.len() < 64:
        key.concat(newSeq[byte](64 - key.len()))
      else:
        key
    innerHash = keyPadded.
                  mapIt(it xor 0x36'u8).
                  concat(msg).
                  mapIt(it.chr).
                  secureHash()
    outerHash = keyPadded.
                  mapIt(it xor 0x5c'u8).
                  concat(@(innerHash.distinctBase)).
                  mapIt(it.chr).
                  secureHash()
  return @(outerHash.distinctBase)
