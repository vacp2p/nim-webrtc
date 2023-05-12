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
{.compile: "./mbedtls/library/ripemd160.c".}
# Generated @ 2023-05-11T11:19:13+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/ripemd160.h

{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
type
  mbedtls_ripemd160_context* {.bycopy.} = object
    private_total*: array[2, uint32]
    private_state*: array[5, uint32]
    private_buffer*: array[64, byte]

proc mbedtls_ripemd160_init*(ctx: ptr mbedtls_ripemd160_context) {.importc,
    cdecl.}
proc mbedtls_ripemd160_free*(ctx: ptr mbedtls_ripemd160_context) {.importc,
    cdecl.}
proc mbedtls_ripemd160_clone*(dst: ptr mbedtls_ripemd160_context;
                              src: ptr mbedtls_ripemd160_context) {.importc,
    cdecl.}
proc mbedtls_ripemd160_starts*(ctx: ptr mbedtls_ripemd160_context): cint {.
    importc, cdecl.}
proc mbedtls_ripemd160_update*(ctx: ptr mbedtls_ripemd160_context;
                               input: ptr byte; ilen: uint): cint {.importc,
    cdecl.}
proc mbedtls_ripemd160_finish*(ctx: ptr mbedtls_ripemd160_context;
                               output: array[20, byte]): cint {.importc, cdecl.}
proc mbedtls_internal_ripemd160_process*(ctx: ptr mbedtls_ripemd160_context;
    data: array[64, byte]): cint {.importc, cdecl.}
proc mbedtls_ripemd160*(input: ptr byte; ilen: uint; output: array[20, byte]): cint {.
    importc, cdecl.}
proc mbedtls_ripemd160_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
