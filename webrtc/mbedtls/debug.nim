#import strformat, os
#
## C include directory
#const root = currentSourcePath.parentDir
#const mbedtlsInclude = root/"mbedtls"/"include"
#const mbedtlsLibrary = root/"mbedtls"/"library"
#
#{.passc: fmt"-I{mbedtlsInclude} -I{mbedtlsLibrary}".}
#
import "build_info"
import "mbedtls_config"
import "config_psa"
import "check_config"
import "ssl"
import "platform_util"
import "platform_time"
import "private_access"
import "bignum"
import "ecp"
import "ssl_ciphersuites"
import "pk"
import "md"
import "rsa"
import "ecdsa"
import "cipher"
import "x509_crt"
import "x509"
import "asn1"
import "x509_crl"
import "dhm"
import "ecdh"
import "md5"
import "ripemd160"
import "sha1"
import "sha256"
import "sha512"
import "cmac"
import "gcm"
import "ccm"
import "chachapoly"
import "poly1305"
import "chacha20"
import "ecjpake"
{.compile: "./mbedtls/library/debug.c".}
# Generated @ 2023-05-11T11:19:09+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/debug.h

# const 'MBEDTLS_PRINTF_MS_TIME' has unsupported value 'PRId64'
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
defineEnum(mbedtls_debug_ecdh_attr)
const
  MBEDTLS_PRINTF_SIZET* = "zu"
  MBEDTLS_PRINTF_LONGLONG* = "lld"
  MBEDTLS_DEBUG_ECDH_Q* = (0).mbedtls_debug_ecdh_attr
  MBEDTLS_DEBUG_ECDH_QP* = (MBEDTLS_DEBUG_ECDH_Q + 1).mbedtls_debug_ecdh_attr
  MBEDTLS_DEBUG_ECDH_Z* = (MBEDTLS_DEBUG_ECDH_QP + 1).mbedtls_debug_ecdh_attr
proc mbedtls_debug_set_threshold*(threshold: cint) {.importc, cdecl.}
proc mbedtls_debug_print_msg*(ssl: ptr mbedtls_ssl_context; level: cint;
                              file: cstring; line: cint; format: cstring) {.
    importc, cdecl, varargs.}
proc mbedtls_debug_print_ret*(ssl: ptr mbedtls_ssl_context; level: cint;
                              file: cstring; line: cint; text: cstring;
                              ret: cint) {.importc, cdecl.}
proc mbedtls_debug_print_buf*(ssl: ptr mbedtls_ssl_context; level: cint;
                              file: cstring; line: cint; text: cstring;
                              buf: ptr byte; len: uint) {.importc, cdecl.}
proc mbedtls_debug_print_mpi*(ssl: ptr mbedtls_ssl_context; level: cint;
                              file: cstring; line: cint; text: cstring;
                              X: ptr mbedtls_mpi) {.importc, cdecl.}
proc mbedtls_debug_print_ecp*(ssl: ptr mbedtls_ssl_context; level: cint;
                              file: cstring; line: cint; text: cstring;
                              X: ptr mbedtls_ecp_point) {.importc, cdecl.}
proc mbedtls_debug_print_crt*(ssl: ptr mbedtls_ssl_context; level: cint;
                              file: cstring; line: cint; text: cstring;
                              crt: ptr mbedtls_x509_crt) {.importc, cdecl.}
proc mbedtls_debug_printf_ecdh*(ssl: ptr mbedtls_ssl_context; level: cint;
                                file: cstring; line: cint;
                                ecdh: ptr mbedtls_ecdh_context;
                                attr: mbedtls_debug_ecdh_attr) {.importc, cdecl.}
{.pop.}
