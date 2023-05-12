#import strformat, os
#
## C include directory
#const root = currentSourcePath.parentDir
#const mbedtlsInclude = root/"mbedtls"/"include"
#const mbedtlsLibrary = root/"mbedtls"/"library"
#
#{.passc: fmt"-I{mbedtlsInclude} -I{mbedtlsLibrary}".}
#
import "asn1"
import "platform_time"
import "x509"
import "pk"
import "md"
import "rsa"
import "ecp"
import "ecdsa"
import "x509_crt"
import "x509_crl"
{.compile: "./mbedtls/library/pkcs7.c".}
# Generated @ 2023-05-11T11:19:12+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/pkcs7.h

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
defineEnum(mbedtls_pkcs7_type)
const
  MBEDTLS_ERR_PKCS7_INVALID_FORMAT* = -0x00005300
  MBEDTLS_ERR_PKCS7_FEATURE_UNAVAILABLE* = -0x00005380
  MBEDTLS_ERR_PKCS7_INVALID_VERSION* = -0x00005400
  MBEDTLS_ERR_PKCS7_INVALID_CONTENT_INFO* = -0x00005480
  MBEDTLS_ERR_PKCS7_INVALID_ALG* = -0x00005500
  MBEDTLS_ERR_PKCS7_INVALID_CERT* = -0x00005580
  MBEDTLS_ERR_PKCS7_INVALID_SIGNATURE* = -0x00005600
  MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO* = -0x00005680
  MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA* = -0x00005700
  MBEDTLS_ERR_PKCS7_ALLOC_FAILED* = -0x00005780
  MBEDTLS_ERR_PKCS7_VERIFY_FAIL* = -0x00005800
  MBEDTLS_ERR_PKCS7_CERT_DATE_INVALID* = -0x00005880
  MBEDTLS_PKCS7_SUPPORTED_VERSION* = 0x00000001
  MBEDTLS_PKCS7_NONE* = (0).mbedtls_pkcs7_type
  MBEDTLS_PKCS7_DATA* = (MBEDTLS_PKCS7_NONE + 1).mbedtls_pkcs7_type
  MBEDTLS_PKCS7_SIGNED_DATA* = (MBEDTLS_PKCS7_DATA + 1).mbedtls_pkcs7_type
  MBEDTLS_PKCS7_ENVELOPED_DATA* = (MBEDTLS_PKCS7_SIGNED_DATA + 1).mbedtls_pkcs7_type
  MBEDTLS_PKCS7_SIGNED_AND_ENVELOPED_DATA* = (MBEDTLS_PKCS7_ENVELOPED_DATA + 1).mbedtls_pkcs7_type
  MBEDTLS_PKCS7_DIGESTED_DATA* = (MBEDTLS_PKCS7_SIGNED_AND_ENVELOPED_DATA + 1).mbedtls_pkcs7_type
  MBEDTLS_PKCS7_ENCRYPTED_DATA* = (MBEDTLS_PKCS7_DIGESTED_DATA + 1).mbedtls_pkcs7_type
type
  mbedtls_pkcs7_buf* = mbedtls_asn1_buf
  mbedtls_pkcs7_name* = mbedtls_asn1_named_data
  mbedtls_pkcs7_sequence* = mbedtls_asn1_sequence
  mbedtls_pkcs7_signer_info* {.bycopy.} = object
    private_version*: cint
    private_serial*: mbedtls_x509_buf
    private_issuer*: mbedtls_x509_name
    private_issuer_raw*: mbedtls_x509_buf
    private_alg_identifier*: mbedtls_x509_buf
    private_sig_alg_identifier*: mbedtls_x509_buf
    private_sig*: mbedtls_x509_buf
    private_next*: ptr mbedtls_pkcs7_signer_info

  mbedtls_pkcs7_signed_data* {.bycopy.} = object
    private_version*: cint
    private_digest_alg_identifiers*: mbedtls_pkcs7_buf
    private_no_of_certs*: cint
    private_certs*: mbedtls_x509_crt
    private_no_of_crls*: cint
    private_crl*: mbedtls_x509_crl
    private_no_of_signers*: cint
    private_signers*: mbedtls_pkcs7_signer_info

  mbedtls_pkcs7* {.bycopy.} = object
    private_raw*: mbedtls_pkcs7_buf
    private_signed_data*: mbedtls_pkcs7_signed_data

proc mbedtls_pkcs7_init*(pkcs7: ptr mbedtls_pkcs7) {.importc, cdecl.}
proc mbedtls_pkcs7_parse_der*(pkcs7: ptr mbedtls_pkcs7; buf: ptr byte;
                              buflen: uint): cint {.importc, cdecl.}
proc mbedtls_pkcs7_signed_data_verify*(pkcs7: ptr mbedtls_pkcs7;
                                       cert: ptr mbedtls_x509_crt;
                                       data: ptr byte; datalen: uint): cint {.
    importc, cdecl.}
proc mbedtls_pkcs7_signed_hash_verify*(pkcs7: ptr mbedtls_pkcs7;
                                       cert: ptr mbedtls_x509_crt;
                                       hash: ptr byte; hashlen: uint): cint {.
    importc, cdecl.}
proc mbedtls_pkcs7_free*(pkcs7: ptr mbedtls_pkcs7) {.importc, cdecl.}
{.pop.}
