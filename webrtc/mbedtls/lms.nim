#import strformat, os
#
## C include directory
#const root = currentSourcePath.parentDir
#const mbedtlsInclude = root/"mbedtls"/"include"
#const mbedtlsLibrary = root/"mbedtls"/"library"
#
#{.passc: fmt"-I{mbedtlsInclude} -I{mbedtlsLibrary}".}
#
import "psa/crypto"
{.compile: "./mbedtls/library/lms.c".}
{.compile: "./mbedtls/library/lmots.c".}
# Generated @ 2023-05-11T11:19:11+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/lms.h

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
defineEnum(mbedtls_lms_algorithm_type_t)
defineEnum(mbedtls_lmots_algorithm_type_t)
const
  MBEDTLS_ERR_LMS_BAD_INPUT_DATA* = -0x00000011
  MBEDTLS_ERR_LMS_OUT_OF_PRIVATE_KEYS* = -0x00000013
  MBEDTLS_ERR_LMS_VERIFY_FAILED* = -0x00000015
  MBEDTLS_ERR_LMS_ALLOC_FAILED* = -0x00000017
  MBEDTLS_ERR_LMS_BUFFER_TOO_SMALL* = -0x00000019
  MBEDTLS_LMOTS_N_HASH_LEN_MAX* = (32'u)
  MBEDTLS_LMOTS_P_SIG_DIGIT_COUNT_MAX* = (34'u)
  MBEDTLS_LMOTS_I_KEY_ID_LEN* = (16'u)
  MBEDTLS_LMOTS_Q_LEAF_ID_LEN* = (4'u)
  MBEDTLS_LMOTS_TYPE_LEN* = (4'u)
  MBEDTLS_LMS_TYPE_LEN* = (4)
  MBEDTLS_LMS_M_NODE_BYTES_MAX* = 32
  MBEDTLS_LMS_SHA256_M32_H10* = (0x00000006).mbedtls_lms_algorithm_type_t
  MBEDTLS_LMOTS_SHA256_N32_W8* = (4).mbedtls_lmots_algorithm_type_t
type
  mbedtls_lmots_parameters_t* {.bycopy.} = object
    private_I_key_identifier*: array[(16'u), byte]
    private_q_leaf_identifier*: array[(4'u), byte]
    private_type*: mbedtls_lmots_algorithm_type_t

  mbedtls_lmots_public_t* {.bycopy.} = object
    private_params*: mbedtls_lmots_parameters_t
    private_public_key*: array[(32'u), byte]
    private_have_public_key*: byte

  mbedtls_lms_parameters_t* {.bycopy.} = object
    private_I_key_identifier*: array[(16'u), byte]
    private_otstype*: mbedtls_lmots_algorithm_type_t
    private_type*: mbedtls_lms_algorithm_type_t

  mbedtls_lms_public_t* {.bycopy.} = object
    private_params*: mbedtls_lms_parameters_t
    private_T_1_pub_key*: array[32, byte]
    private_have_public_key*: byte

proc mbedtls_lms_public_init*(ctx: ptr mbedtls_lms_public_t) {.importc, cdecl.}
proc mbedtls_lms_public_free*(ctx: ptr mbedtls_lms_public_t) {.importc, cdecl.}
proc mbedtls_lms_import_public_key*(ctx: ptr mbedtls_lms_public_t;
                                    key: ptr byte; key_size: uint): cint {.
    importc, cdecl.}
proc mbedtls_lms_export_public_key*(ctx: ptr mbedtls_lms_public_t;
                                    key: ptr byte; key_size: uint;
                                    key_len: ptr uint): cint {.importc, cdecl.}
proc mbedtls_lms_verify*(ctx: ptr mbedtls_lms_public_t; msg: ptr byte;
                         msg_size: uint; sig: ptr byte; sig_size: uint): cint {.
    importc, cdecl.}
{.pop.}
