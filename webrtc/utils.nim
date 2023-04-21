import strutils, bitops

proc createCrc32Table(): array[0..255, uint32] =
  for i in 0..255:
    var rem = i.uint32
    for j in 0..7:
      if (rem and 1) > 0: rem = (rem shr 1) xor 0xedb88320'u32
      else: rem = rem shr 1
    result[i] = rem

proc crc32*(s: seq[byte]): uint32 =
  const crc32table = createCrc32Table()
  result = 0xffffffff'u32
  for c in s:
    result = (result shr 8) xor crc32table[(result and 0xff) xor c]
  result = not result
