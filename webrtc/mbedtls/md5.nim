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
{.compile: "./mbedtls/library/md5.c".}
# Generated @ 2023-05-11T11:19:11+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/md5.h

{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
type
  mbedtls_md5_context* {.bycopy.} = object
    private_total*: array[2, uint32]
    private_state*: array[4, uint32]
    private_buffer*: array[64, byte]

proc mbedtls_md5_init*(ctx: ptr mbedtls_md5_context) {.importc, cdecl.}
proc mbedtls_md5_free*(ctx: ptr mbedtls_md5_context) {.importc, cdecl.}
proc mbedtls_md5_clone*(dst: ptr mbedtls_md5_context;
                        src: ptr mbedtls_md5_context) {.importc, cdecl.}
proc mbedtls_md5_starts*(ctx: ptr mbedtls_md5_context): cint {.importc, cdecl.}
proc mbedtls_md5_update*(ctx: ptr mbedtls_md5_context; input: ptr byte;
                         ilen: uint): cint {.importc, cdecl.}
proc mbedtls_md5_finish*(ctx: ptr mbedtls_md5_context; output: array[16, byte]): cint {.
    importc, cdecl.}
proc mbedtls_internal_md5_process*(ctx: ptr mbedtls_md5_context;
                                   data: array[64, byte]): cint {.importc,
    cdecl.}
proc mbedtls_md5*(input: ptr byte; ilen: uint; output: array[16, byte]): cint {.
    importc, cdecl.}
proc mbedtls_md5_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
