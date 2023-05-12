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
{.compile: "./mbedtls/library/sha512.c".}
# Generated @ 2023-05-11T11:19:13+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/sha512.h

{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
const
  MBEDTLS_ERR_SHA512_BAD_INPUT_DATA* = -0x00000075
type
  mbedtls_sha512_context* {.bycopy.} = object
    private_total*: array[2, uint64]
    private_state*: array[8, uint64]
    private_buffer*: array[128, byte]
    private_is384*: cint

proc mbedtls_sha512_init*(ctx: ptr mbedtls_sha512_context) {.importc, cdecl.}
proc mbedtls_sha512_free*(ctx: ptr mbedtls_sha512_context) {.importc, cdecl.}
proc mbedtls_sha512_clone*(dst: ptr mbedtls_sha512_context;
                           src: ptr mbedtls_sha512_context) {.importc, cdecl.}
proc mbedtls_sha512_starts*(ctx: ptr mbedtls_sha512_context; is384: cint): cint {.
    importc, cdecl.}
proc mbedtls_sha512_update*(ctx: ptr mbedtls_sha512_context; input: ptr byte;
                            ilen: uint): cint {.importc, cdecl.}
proc mbedtls_sha512_finish*(ctx: ptr mbedtls_sha512_context; output: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_internal_sha512_process*(ctx: ptr mbedtls_sha512_context;
                                      data: array[128, byte]): cint {.importc,
    cdecl.}
proc mbedtls_sha512*(input: ptr byte; ilen: uint; output: ptr byte;
                     is384: cint): cint {.importc, cdecl.}
proc mbedtls_sha384_self_test*(verbose: cint): cint {.importc, cdecl.}
proc mbedtls_sha512_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
