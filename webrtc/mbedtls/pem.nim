#import strformat, os
#
## C include directory
#const root = currentSourcePath.parentDir
#const mbedtlsInclude = root/"mbedtls"/"include"
#const mbedtlsLibrary = root/"mbedtls"/"library"
#
#{.passc: fmt"-I{mbedtlsInclude} -I{mbedtlsLibrary}".}
#
import "aes"
import "base64"
import "des"
import "constant_time"
{.compile: "./mbedtls/library/pem.c".}
# Generated @ 2023-05-11T11:19:12+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/pem.h

# proc 'mbedtls_pem_get_buffer' skipped - static inline procs cannot work with '--noHeader | -H'
{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
const
  MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT* = -0x00001080
  MBEDTLS_ERR_PEM_INVALID_DATA* = -0x00001100
  MBEDTLS_ERR_PEM_ALLOC_FAILED* = -0x00001180
  MBEDTLS_ERR_PEM_INVALID_ENC_IV* = -0x00001200
  MBEDTLS_ERR_PEM_UNKNOWN_ENC_ALG* = -0x00001280
  MBEDTLS_ERR_PEM_PASSWORD_REQUIRED* = -0x00001300
  MBEDTLS_ERR_PEM_PASSWORD_MISMATCH* = -0x00001380
  MBEDTLS_ERR_PEM_FEATURE_UNAVAILABLE* = -0x00001400
  MBEDTLS_ERR_PEM_BAD_INPUT_DATA* = -0x00001480
type
  mbedtls_pem_context* {.bycopy.} = object
    private_buf*: ptr byte
    private_buflen*: uint
    private_info*: ptr byte

proc mbedtls_pem_init*(ctx: ptr mbedtls_pem_context) {.importc, cdecl.}
proc mbedtls_pem_read_buffer*(ctx: ptr mbedtls_pem_context; header: cstring;
                              footer: cstring; data: ptr byte;
                              pwd: ptr byte; pwdlen: uint; use_len: ptr uint): cint {.
    importc, cdecl.}
proc mbedtls_pem_free*(ctx: ptr mbedtls_pem_context) {.importc, cdecl.}
proc mbedtls_pem_write_buffer*(header: cstring; footer: cstring;
                               der_data: ptr byte; der_len: uint;
                               buf: ptr byte; buf_len: uint; olen: ptr uint): cint {.
    importc, cdecl.}
{.pop.}
