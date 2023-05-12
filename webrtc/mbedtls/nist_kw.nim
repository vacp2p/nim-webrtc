#import strformat, os
#
## C include directory
#const root = currentSourcePath.parentDir
#const mbedtlsInclude = root/"mbedtls"/"include"
#const mbedtlsLibrary = root/"mbedtls"/"library"
#
#{.passc: fmt"-I{mbedtlsInclude} -I{mbedtlsLibrary}".}
#
import "private_access"
import "build_info"
import "mbedtls_config"
import "config_psa"
import "check_config"
import "cipher"
import "platform_util"
import "platform_time"
# Generated @ 2023-05-11T11:19:11+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/nist_kw.h

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
defineEnum(mbedtls_nist_kw_mode_t)
const
  MBEDTLS_KW_MODE_KW* = (0).mbedtls_nist_kw_mode_t
  MBEDTLS_KW_MODE_KWP* = (1).mbedtls_nist_kw_mode_t
type
  mbedtls_nist_kw_context* {.bycopy.} = object
    private_cipher_ctx*: mbedtls_cipher_context_t

proc mbedtls_nist_kw_init*(ctx: ptr mbedtls_nist_kw_context) {.importc, cdecl.}
proc mbedtls_nist_kw_setkey*(ctx: ptr mbedtls_nist_kw_context;
                             cipher: mbedtls_cipher_id_t; key: ptr byte;
                             keybits: cuint; is_wrap: cint): cint {.importc,
    cdecl.}
proc mbedtls_nist_kw_free*(ctx: ptr mbedtls_nist_kw_context) {.importc, cdecl.}
proc mbedtls_nist_kw_wrap*(ctx: ptr mbedtls_nist_kw_context;
                           mode: mbedtls_nist_kw_mode_t; input: ptr byte;
                           in_len: uint; output: ptr byte; out_len: ptr uint;
                           out_size: uint): cint {.importc, cdecl.}
proc mbedtls_nist_kw_unwrap*(ctx: ptr mbedtls_nist_kw_context;
                             mode: mbedtls_nist_kw_mode_t; input: ptr byte;
                             in_len: uint; output: ptr byte;
                             out_len: ptr uint; out_size: uint): cint {.importc,
    cdecl.}
proc mbedtls_nist_kw_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
