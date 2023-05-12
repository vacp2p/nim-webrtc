#import strformat, os
#
## C include directory
#const root = currentSourcePath.parentDir
#const mbedtlsInclude = root/"mbedtls"/"include"
#const mbedtlsLibrary = root/"mbedtls"/"library"
#
#{.passc: fmt"-I{mbedtlsInclude} -I{mbedtlsLibrary}".}
#
import "platform_time"
import "ripemd160"
import "sha1"
import "sha256"
import "sha512"
import "md5"
# {.compile: "./mbedtls/library/ripemd160.c".}
# {.compile: "./mbedtls/library/sha1.c".}
# {.compile: "./mbedtls/library/sha256.c".}
# {.compile: "./mbedtls/library/sha512.c".}
# {.compile: "./mbedtls/library/md5.c".}
{.compile: "./mbedtls/library/md.c".}
# Generated @ 2023-05-11T11:19:11+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/md.h

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
defineEnum(mbedtls_md_type_t)
defineEnum(mbedtls_md_engine_t)
const
  MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE* = -0x00005080
  MBEDTLS_ERR_MD_BAD_INPUT_DATA* = -0x00005100
  MBEDTLS_ERR_MD_ALLOC_FAILED* = -0x00005180
  MBEDTLS_ERR_MD_FILE_IO_ERROR* = -0x00005200
  MBEDTLS_MD_NONE* = (0).mbedtls_md_type_t
  MBEDTLS_MD_MD5* = (MBEDTLS_MD_NONE + 1).mbedtls_md_type_t
  MBEDTLS_MD_SHA1* = (MBEDTLS_MD_MD5 + 1).mbedtls_md_type_t
  MBEDTLS_MD_SHA224* = (MBEDTLS_MD_SHA1 + 1).mbedtls_md_type_t
  MBEDTLS_MD_SHA256* = (MBEDTLS_MD_SHA224 + 1).mbedtls_md_type_t
  MBEDTLS_MD_SHA384* = (MBEDTLS_MD_SHA256 + 1).mbedtls_md_type_t
  MBEDTLS_MD_SHA512* = (MBEDTLS_MD_SHA384 + 1).mbedtls_md_type_t
  MBEDTLS_MD_RIPEMD160* = (MBEDTLS_MD_SHA512 + 1).mbedtls_md_type_t
  MBEDTLS_MD_MAX_SIZE* = 64
  MBEDTLS_MD_MAX_BLOCK_SIZE* = 128
  MBEDTLS_MD_ENGINE_LEGACY* = (0).mbedtls_md_engine_t
  MBEDTLS_MD_ENGINE_PSA* = (MBEDTLS_MD_ENGINE_LEGACY + 1).mbedtls_md_engine_t
type
  mbedtls_md_info_t* {.incompleteStruct.} = object
  mbedtls_md_context_t* {.bycopy.} = object
    private_md_info*: ptr mbedtls_md_info_t
    private_md_ctx*: pointer
    private_hmac_ctx*: pointer

proc mbedtls_md_info_from_type*(md_type: mbedtls_md_type_t): ptr mbedtls_md_info_t {.
    importc, cdecl.}
proc mbedtls_md_init*(ctx: ptr mbedtls_md_context_t) {.importc, cdecl.}
proc mbedtls_md_free*(ctx: ptr mbedtls_md_context_t) {.importc, cdecl.}
proc mbedtls_md_setup*(ctx: ptr mbedtls_md_context_t;
                       md_info: ptr mbedtls_md_info_t; hmac: cint): cint {.
    importc, cdecl.}
proc mbedtls_md_clone*(dst: ptr mbedtls_md_context_t;
                       src: ptr mbedtls_md_context_t): cint {.importc, cdecl.}
proc mbedtls_md_get_size*(md_info: ptr mbedtls_md_info_t): byte {.importc,
    cdecl.}
proc mbedtls_md_get_type*(md_info: ptr mbedtls_md_info_t): mbedtls_md_type_t {.
    importc, cdecl.}
proc mbedtls_md_starts*(ctx: ptr mbedtls_md_context_t): cint {.importc, cdecl.}
proc mbedtls_md_update*(ctx: ptr mbedtls_md_context_t; input: ptr byte;
                        ilen: uint): cint {.importc, cdecl.}
proc mbedtls_md_finish*(ctx: ptr mbedtls_md_context_t; output: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_md*(md_info: ptr mbedtls_md_info_t; input: ptr byte; ilen: uint;
                 output: ptr byte): cint {.importc, cdecl.}
proc mbedtls_md_list*(): ptr cint {.importc, cdecl.}
proc mbedtls_md_info_from_string*(md_name: cstring): ptr mbedtls_md_info_t {.
    importc, cdecl.}
proc mbedtls_md_get_name*(md_info: ptr mbedtls_md_info_t): cstring {.importc,
    cdecl.}
proc mbedtls_md_info_from_ctx*(ctx: ptr mbedtls_md_context_t): ptr mbedtls_md_info_t {.
    importc, cdecl.}
proc mbedtls_md_file*(md_info: ptr mbedtls_md_info_t; path: cstring;
                      output: ptr byte): cint {.importc, cdecl.}
proc mbedtls_md_hmac_starts*(ctx: ptr mbedtls_md_context_t; key: ptr byte;
                             keylen: uint): cint {.importc, cdecl.}
proc mbedtls_md_hmac_update*(ctx: ptr mbedtls_md_context_t; input: ptr byte;
                             ilen: uint): cint {.importc, cdecl.}
proc mbedtls_md_hmac_finish*(ctx: ptr mbedtls_md_context_t; output: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_md_hmac_reset*(ctx: ptr mbedtls_md_context_t): cint {.importc,
    cdecl.}
proc mbedtls_md_hmac*(md_info: ptr mbedtls_md_info_t; key: ptr byte;
                      keylen: uint; input: ptr byte; ilen: uint;
                      output: ptr byte): cint {.importc, cdecl.}
{.pop.}
