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
{.compile: "./mbedtls/library/chacha20.c".}
# Generated @ 2023-05-11T11:19:08+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/chacha20.h

{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
const
  MBEDTLS_ERR_CHACHA20_BAD_INPUT_DATA* = -0x00000051
type
  mbedtls_chacha20_context* {.bycopy.} = object
    private_state*: array[16, uint32]
    private_keystream8*: array[64, uint8]
    private_keystream_bytes_used*: uint

proc mbedtls_chacha20_init*(ctx: ptr mbedtls_chacha20_context) {.importc, cdecl.}
proc mbedtls_chacha20_free*(ctx: ptr mbedtls_chacha20_context) {.importc, cdecl.}
proc mbedtls_chacha20_setkey*(ctx: ptr mbedtls_chacha20_context;
                              key: array[32, byte]): cint {.importc, cdecl.}
proc mbedtls_chacha20_starts*(ctx: ptr mbedtls_chacha20_context;
                              nonce: array[12, byte]; counter: uint32): cint {.
    importc, cdecl.}
proc mbedtls_chacha20_update*(ctx: ptr mbedtls_chacha20_context; size: uint;
                              input: ptr byte; output: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_chacha20_crypt*(key: array[32, byte]; nonce: array[12, byte];
                             counter: uint32; size: uint; input: ptr byte;
                             output: ptr byte): cint {.importc, cdecl.}
proc mbedtls_chacha20_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
