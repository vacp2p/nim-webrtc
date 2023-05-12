#import strformat, os
#
## C include directory
#const root = currentSourcePath.parentDir
#const mbedtlsInclude = root/"mbedtls"/"include"
#const mbedtlsLibrary = root/"mbedtls"/"library"
#
#{.passc: fmt"-I{mbedtlsInclude} -I{mbedtlsLibrary}".}
#
import "poly1305"
import "chacha20"
{.compile: "./mbedtls/library/chachapoly.c".}
# Generated @ 2023-05-11T11:19:08+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/chachapoly.h

{.push hint[ConvFromXtoItselfNotNeeded]: off.}
import macros

macro defineEnum(typ: untyped): untyped =
  result = newNimNode(nnkStmtList)

  # Enum mapped to distinct cint
  result.add quote do:
    type `typ`* = distinct cint

  for i in ["+", "-", "*", "div", "mod", "shl", "shr", "or", "and", "xor", "<", "<=", "==", ">", ">="]:
    let
      ni = newIdentNode(i)
      typout = if i[0] in "<=>": newIdentNode("bool") else: typ # comparisons return bool
    if i[0] == '>': # cannot borrow `>` and `>=` from templates
      let
        nopp = if i.len == 2: newIdentNode("<=") else: newIdentNode("<")
      result.add quote do:
        proc `ni`*(x: `typ`, y: cint): `typout` = `nopp`(y, x)
        proc `ni`*(x: cint, y: `typ`): `typout` = `nopp`(y, x)
        proc `ni`*(x, y: `typ`): `typout` = `nopp`(y, x)
    else:
      result.add quote do:
        proc `ni`*(x: `typ`, y: cint): `typout` {.borrow.}
        proc `ni`*(x: cint, y: `typ`): `typout` {.borrow.}
        proc `ni`*(x, y: `typ`): `typout` {.borrow.}
    result.add quote do:
      proc `ni`*(x: `typ`, y: int): `typout` = `ni`(x, y.cint)
      proc `ni`*(x: int, y: `typ`): `typout` = `ni`(x.cint, y)

  let
    divop = newIdentNode("/")   # `/`()
    dlrop = newIdentNode("$")   # `$`()
    notop = newIdentNode("not") # `not`()
  result.add quote do:
    proc `divop`*(x, y: `typ`): `typ` = `typ`((x.float / y.float).cint)
    proc `divop`*(x: `typ`, y: cint): `typ` = `divop`(x, `typ`(y))
    proc `divop`*(x: cint, y: `typ`): `typ` = `divop`(`typ`(x), y)
    proc `divop`*(x: `typ`, y: int): `typ` = `divop`(x, y.cint)
    proc `divop`*(x: int, y: `typ`): `typ` = `divop`(x.cint, y)

    proc `dlrop`*(x: `typ`): string {.borrow.}
    proc `notop`*(x: `typ`): `typ` {.borrow.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
defineEnum(mbedtls_chachapoly_mode_t)
const
  MBEDTLS_ERR_CHACHAPOLY_BAD_STATE* = -0x00000054
  MBEDTLS_ERR_CHACHAPOLY_AUTH_FAILED* = -0x00000056
  MBEDTLS_CHACHAPOLY_ENCRYPT* = (0).mbedtls_chachapoly_mode_t
  MBEDTLS_CHACHAPOLY_DECRYPT* = (MBEDTLS_CHACHAPOLY_ENCRYPT + 1).mbedtls_chachapoly_mode_t
type
  mbedtls_chachapoly_context* {.bycopy.} = object
    private_chacha20_ctx*: mbedtls_chacha20_context
    private_poly1305_ctx*: mbedtls_poly1305_context
    private_aad_len*: uint64
    private_ciphertext_len*: uint64
    private_state*: cint
    private_mode*: mbedtls_chachapoly_mode_t

proc mbedtls_chachapoly_init*(ctx: ptr mbedtls_chachapoly_context) {.importc,
    cdecl.}
proc mbedtls_chachapoly_free*(ctx: ptr mbedtls_chachapoly_context) {.importc,
    cdecl.}
proc mbedtls_chachapoly_setkey*(ctx: ptr mbedtls_chachapoly_context;
                                key: array[32, byte]): cint {.importc, cdecl.}
proc mbedtls_chachapoly_starts*(ctx: ptr mbedtls_chachapoly_context;
                                nonce: array[12, byte];
                                mode: mbedtls_chachapoly_mode_t): cint {.
    importc, cdecl.}
proc mbedtls_chachapoly_update_aad*(ctx: ptr mbedtls_chachapoly_context;
                                    aad: ptr byte; aad_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_chachapoly_update*(ctx: ptr mbedtls_chachapoly_context; len: uint;
                                input: ptr byte; output: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_chachapoly_finish*(ctx: ptr mbedtls_chachapoly_context;
                                mac: array[16, byte]): cint {.importc, cdecl.}
proc mbedtls_chachapoly_encrypt_and_tag*(ctx: ptr mbedtls_chachapoly_context;
    length: uint; nonce: array[12, byte]; aad: ptr byte; aad_len: uint;
    input: ptr byte; output: ptr byte; tag: array[16, byte]): cint {.
    importc, cdecl.}
proc mbedtls_chachapoly_auth_decrypt*(ctx: ptr mbedtls_chachapoly_context;
                                      length: uint; nonce: array[12, byte];
                                      aad: ptr byte; aad_len: uint;
                                      tag: array[16, byte]; input: ptr byte;
                                      output: ptr byte): cint {.importc, cdecl.}
proc mbedtls_chachapoly_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
