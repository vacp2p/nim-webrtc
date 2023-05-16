import "bignum"
# TODO: Remove bignum, it's not used in this file.

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
proc mbedtls_ct_memcmp*(a: pointer; b: pointer; n: uint): cint {.importc, cdecl.}
{.pop.}
