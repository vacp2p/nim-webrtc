#import strformat, os
#
## C include directory
#const root = currentSourcePath.parentDir
#const mbedtlsInclude = root/"mbedtls"/"include"
#const mbedtlsLibrary = root/"mbedtls"/"library"
#
#{.passc: fmt"-I{mbedtlsInclude} -I{mbedtlsLibrary}".}
#
import "md"
{.compile: "./mbedtls/library/poly1305.c".}
# Generated @ 2023-05-11T11:19:12+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/poly1305.h

{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
const
  MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA* = -0x00000057
type
  mbedtls_poly1305_context* {.bycopy.} = object
    private_r*: array[4, uint32]
    private_s*: array[4, uint32]
    private_acc*: array[5, uint32]
    private_queue*: array[16, uint8]
    private_queue_len*: uint

proc mbedtls_poly1305_init*(ctx: ptr mbedtls_poly1305_context) {.importc, cdecl.}
proc mbedtls_poly1305_free*(ctx: ptr mbedtls_poly1305_context) {.importc, cdecl.}
proc mbedtls_poly1305_starts*(ctx: ptr mbedtls_poly1305_context;
                              key: array[32, byte]): cint {.importc, cdecl.}
proc mbedtls_poly1305_update*(ctx: ptr mbedtls_poly1305_context;
                              input: ptr byte; ilen: uint): cint {.importc,
    cdecl.}
proc mbedtls_poly1305_finish*(ctx: ptr mbedtls_poly1305_context;
                              mac: array[16, byte]): cint {.importc, cdecl.}
proc mbedtls_poly1305_mac*(key: array[32, byte]; input: ptr byte;
                           ilen: uint; mac: array[16, byte]): cint {.importc,
    cdecl.}
proc mbedtls_poly1305_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
