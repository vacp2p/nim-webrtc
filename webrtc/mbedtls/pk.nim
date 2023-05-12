#import strformat, os
#
## C include directory
#const root = currentSourcePath.parentDir
#const mbedtlsInclude = root/"mbedtls"/"include"
#const mbedtlsLibrary = root/"mbedtls"/"library"
#
#{.passc: fmt"-I{mbedtlsInclude} -I{mbedtlsLibrary}".}
#
import "pem"
import "md"
import "platform_time"
import "rsa"
import "ecp"
import "ecdh"
import "ecdsa"
import "psa_util"
import "psa/crypto"
{.compile: "./mbedtls/library/pk_wrap.c".}
{.compile: "./mbedtls/library/pk.c".}
{.compile: "./mbedtls/library/pkparse.c".}
{.compile: "./mbedtls/library/pkwrite.c".}
# Generated @ 2023-05-11T11:19:12+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/pk.h

# const 'MBEDTLS_PK_SIGNATURE_MAX_SIZE' has unsupported value 'MBEDTLS_MPI_MAX_SIZE'
# proc 'mbedtls_pk_get_len' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_pk_rsa' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_pk_ec' skipped - static inline procs cannot work with '--noHeader | -H'
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
defineEnum(mbedtls_pk_type_t)
defineEnum(mbedtls_pk_debug_type)
const
  MBEDTLS_ERR_PK_ALLOC_FAILED* = -0x00003F80
  MBEDTLS_ERR_PK_TYPE_MISMATCH* = -0x00003F00
  MBEDTLS_ERR_PK_BAD_INPUT_DATA* = -0x00003E80
  MBEDTLS_ERR_PK_FILE_IO_ERROR* = -0x00003E00
  MBEDTLS_ERR_PK_KEY_INVALID_VERSION* = -0x00003D80
  MBEDTLS_ERR_PK_KEY_INVALID_FORMAT* = -0x00003D00
  MBEDTLS_ERR_PK_UNKNOWN_PK_ALG* = -0x00003C80
  MBEDTLS_ERR_PK_PASSWORD_REQUIRED* = -0x00003C00
  MBEDTLS_ERR_PK_PASSWORD_MISMATCH* = -0x00003B80
  MBEDTLS_ERR_PK_INVALID_PUBKEY* = -0x00003B00
  MBEDTLS_ERR_PK_INVALID_ALG* = -0x00003A80
  MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE* = -0x00003A00
  MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE* = -0x00003980
  MBEDTLS_ERR_PK_SIG_LEN_MISMATCH* = -0x00003900
  MBEDTLS_ERR_PK_BUFFER_TOO_SMALL* = -0x00003880
  MBEDTLS_PK_NONE* = (0).mbedtls_pk_type_t
  MBEDTLS_PK_RSA* = (MBEDTLS_PK_NONE + 1).mbedtls_pk_type_t
  MBEDTLS_PK_ECKEY* = (MBEDTLS_PK_RSA + 1).mbedtls_pk_type_t
  MBEDTLS_PK_ECKEY_DH* = (MBEDTLS_PK_ECKEY + 1).mbedtls_pk_type_t
  MBEDTLS_PK_ECDSA* = (MBEDTLS_PK_ECKEY_DH + 1).mbedtls_pk_type_t
  MBEDTLS_PK_RSA_ALT* = (MBEDTLS_PK_ECDSA + 1).mbedtls_pk_type_t
  MBEDTLS_PK_RSASSA_PSS* = (MBEDTLS_PK_RSA_ALT + 1).mbedtls_pk_type_t
  MBEDTLS_PK_OPAQUE* = (MBEDTLS_PK_RSASSA_PSS + 1).mbedtls_pk_type_t
  MBEDTLS_PK_SIGNATURE_MAX_SIZE* = 0
  MBEDTLS_PK_DEBUG_NONE* = (0).mbedtls_pk_debug_type
  MBEDTLS_PK_DEBUG_MPI* = (MBEDTLS_PK_DEBUG_NONE + 1).mbedtls_pk_debug_type
  MBEDTLS_PK_DEBUG_ECP* = (MBEDTLS_PK_DEBUG_MPI + 1).mbedtls_pk_debug_type
  MBEDTLS_PK_DEBUG_MAX_ITEMS* = 3
type
  mbedtls_pk_rsassa_pss_options* {.bycopy.} = object
    mgf1_hash_id*: mbedtls_md_type_t
    expected_salt_len*: cint

  mbedtls_pk_debug_item* {.bycopy.} = object
    private_type*: mbedtls_pk_debug_type
    private_name*: cstring
    private_value*: pointer

  mbedtls_pk_info_t* {.incompleteStruct.} = object
  mbedtls_pk_context* {.bycopy.} = object
    private_pk_info*: ptr mbedtls_pk_info_t
    private_pk_ctx*: pointer

  mbedtls_pk_restart_ctx* = object
  mbedtls_pk_rsa_alt_decrypt_func* = proc (ctx: pointer; olen: ptr uint;
      input: ptr byte; output: ptr byte; output_max_len: uint): cint {.cdecl.}
  mbedtls_pk_rsa_alt_sign_func* = proc (ctx: pointer; f_rng: proc (a1: pointer;
      a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer;
                                        md_alg: mbedtls_md_type_t;
                                        hashlen: cuint; hash: ptr byte;
                                        sig: ptr byte): cint {.cdecl.}
  mbedtls_pk_rsa_alt_key_len_func* = proc (ctx: pointer): uint {.cdecl.}
proc mbedtls_pk_info_from_type*(pk_type: mbedtls_pk_type_t): ptr mbedtls_pk_info_t {.
    importc, cdecl.}
proc mbedtls_pk_init*(ctx: ptr mbedtls_pk_context) {.importc, cdecl.}
proc mbedtls_pk_free*(ctx: ptr mbedtls_pk_context) {.importc, cdecl.}
proc mbedtls_pk_setup*(ctx: ptr mbedtls_pk_context; info: ptr mbedtls_pk_info_t): cint {.
    importc, cdecl.}
proc mbedtls_pk_setup_rsa_alt*(ctx: ptr mbedtls_pk_context; key: pointer;
                               decrypt_func: mbedtls_pk_rsa_alt_decrypt_func;
                               sign_func: mbedtls_pk_rsa_alt_sign_func;
                               key_len_func: mbedtls_pk_rsa_alt_key_len_func): cint {.
    importc, cdecl.}
proc mbedtls_pk_get_bitlen*(ctx: ptr mbedtls_pk_context): uint {.importc, cdecl.}
proc mbedtls_pk_can_do*(ctx: ptr mbedtls_pk_context; `type`: mbedtls_pk_type_t): cint {.
    importc, cdecl.}
proc mbedtls_pk_verify*(ctx: ptr mbedtls_pk_context; md_alg: mbedtls_md_type_t;
                        hash: ptr byte; hash_len: uint; sig: ptr byte;
                        sig_len: uint): cint {.importc, cdecl.}
proc mbedtls_pk_verify_restartable*(ctx: ptr mbedtls_pk_context;
                                    md_alg: mbedtls_md_type_t; hash: ptr byte;
                                    hash_len: uint; sig: ptr byte;
                                    sig_len: uint;
                                    rs_ctx: ptr mbedtls_pk_restart_ctx): cint {.
    importc, cdecl.}
proc mbedtls_pk_verify_ext*(`type`: mbedtls_pk_type_t; options: pointer;
                            ctx: ptr mbedtls_pk_context;
                            md_alg: mbedtls_md_type_t; hash: ptr byte;
                            hash_len: uint; sig: ptr byte; sig_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_pk_sign*(ctx: ptr mbedtls_pk_context; md_alg: mbedtls_md_type_t;
                      hash: ptr byte; hash_len: uint; sig: ptr byte;
                      sig_size: uint; sig_len: ptr uint; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.
    importc, cdecl.}
proc mbedtls_pk_sign_ext*(pk_type: mbedtls_pk_type_t;
                          ctx: ptr mbedtls_pk_context;
                          md_alg: mbedtls_md_type_t; hash: ptr byte;
                          hash_len: uint; sig: ptr byte; sig_size: uint;
                          sig_len: ptr uint; f_rng: proc (a1: pointer;
    a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.importc,
    cdecl.}
proc mbedtls_pk_sign_restartable*(ctx: ptr mbedtls_pk_context;
                                  md_alg: mbedtls_md_type_t; hash: ptr byte;
                                  hash_len: uint; sig: ptr byte;
                                  sig_size: uint; sig_len: ptr uint; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer;
                                  rs_ctx: ptr mbedtls_pk_restart_ctx): cint {.
    importc, cdecl.}
proc mbedtls_pk_decrypt*(ctx: ptr mbedtls_pk_context; input: ptr byte;
                         ilen: uint; output: ptr byte; olen: ptr uint;
                         osize: uint; f_rng: proc (a1: pointer; a2: ptr byte;
    a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.importc, cdecl.}
proc mbedtls_pk_encrypt*(ctx: ptr mbedtls_pk_context; input: ptr byte;
                         ilen: uint; output: ptr byte; olen: ptr uint;
                         osize: uint; f_rng: proc (a1: pointer; a2: ptr byte;
    a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.importc, cdecl.}
proc mbedtls_pk_check_pair*(pub: ptr mbedtls_pk_context;
                            prv: ptr mbedtls_pk_context; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.
    importc, cdecl.}
proc mbedtls_pk_debug*(ctx: ptr mbedtls_pk_context;
                       items: ptr mbedtls_pk_debug_item): cint {.importc, cdecl.}
proc mbedtls_pk_get_name*(ctx: ptr mbedtls_pk_context): cstring {.importc, cdecl.}
proc mbedtls_pk_get_type*(ctx: ptr mbedtls_pk_context): mbedtls_pk_type_t {.
    importc, cdecl.}
proc mbedtls_pk_parse_key*(ctx: ptr mbedtls_pk_context; key: ptr byte;
                           keylen: uint; pwd: ptr byte; pwdlen: uint; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.
    importc, cdecl.}
proc mbedtls_pk_parse_public_key*(ctx: ptr mbedtls_pk_context; key: ptr byte;
                                  keylen: uint): cint {.importc, cdecl.}
proc mbedtls_pk_parse_keyfile*(ctx: ptr mbedtls_pk_context; path: cstring;
                               password: cstring; f_rng: proc (a1: pointer;
    a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.importc,
    cdecl.}
proc mbedtls_pk_parse_public_keyfile*(ctx: ptr mbedtls_pk_context; path: cstring): cint {.
    importc, cdecl.}
proc mbedtls_pk_write_key_der*(ctx: ptr mbedtls_pk_context; buf: ptr byte;
                               size: uint): cint {.importc, cdecl.}
proc mbedtls_pk_write_pubkey_der*(ctx: ptr mbedtls_pk_context; buf: ptr byte;
                                  size: uint): cint {.importc, cdecl.}
proc mbedtls_pk_write_pubkey_pem*(ctx: ptr mbedtls_pk_context; buf: ptr byte;
                                  size: uint): cint {.importc, cdecl.}
proc mbedtls_pk_write_key_pem*(ctx: ptr mbedtls_pk_context; buf: ptr byte;
                               size: uint): cint {.importc, cdecl.}
proc mbedtls_pk_parse_subpubkey*(p: ptr ptr byte; `end`: ptr byte;
                                 pk: ptr mbedtls_pk_context): cint {.importc,
    cdecl.}
proc mbedtls_pk_write_pubkey*(p: ptr ptr byte; start: ptr byte;
                              key: ptr mbedtls_pk_context): cint {.importc,
    cdecl.}
proc mbedtls_pk_load_file*(path: cstring; buf: ptr ptr byte; n: ptr uint): cint {.
    importc, cdecl.}
{.pop.}
