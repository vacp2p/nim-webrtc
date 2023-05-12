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
{.compile: "./mbedtls/library/aria.c".}
# Generated @ 2023-05-11T11:19:07+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/aria.h

{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
const
  MBEDTLS_ARIA_ENCRYPT* = 1
  MBEDTLS_ARIA_DECRYPT* = 0
  MBEDTLS_ARIA_BLOCKSIZE* = 16
  MBEDTLS_ARIA_MAX_ROUNDS* = 16
  MBEDTLS_ARIA_MAX_KEYSIZE* = 32
  MBEDTLS_ERR_ARIA_BAD_INPUT_DATA* = -0x0000005C
  MBEDTLS_ERR_ARIA_INVALID_INPUT_LENGTH* = -0x0000005E
type
  mbedtls_aria_context* {.bycopy.} = object
    private_nr*: byte
    private_rk*: array[16 + typeof(16)(1),
                       array[typeof(16)(16 / typeof(16)(4)), uint32]]

proc mbedtls_aria_init*(ctx: ptr mbedtls_aria_context) {.importc, cdecl.}
proc mbedtls_aria_free*(ctx: ptr mbedtls_aria_context) {.importc, cdecl.}
proc mbedtls_aria_setkey_enc*(ctx: ptr mbedtls_aria_context; key: ptr byte;
                              keybits: cuint): cint {.importc, cdecl.}
proc mbedtls_aria_setkey_dec*(ctx: ptr mbedtls_aria_context; key: ptr byte;
                              keybits: cuint): cint {.importc, cdecl.}
proc mbedtls_aria_crypt_ecb*(ctx: ptr mbedtls_aria_context;
                             input: array[16, byte]; output: array[16, byte]): cint {.
    importc, cdecl.}
proc mbedtls_aria_crypt_cbc*(ctx: ptr mbedtls_aria_context; mode: cint;
                             length: uint; iv: array[16, byte];
                             input: ptr byte; output: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_aria_crypt_cfb128*(ctx: ptr mbedtls_aria_context; mode: cint;
                                length: uint; iv_off: ptr uint;
                                iv: array[16, byte]; input: ptr byte;
                                output: ptr byte): cint {.importc, cdecl.}
proc mbedtls_aria_crypt_ctr*(ctx: ptr mbedtls_aria_context; length: uint;
                             nc_off: ptr uint; nonce_counter: array[16, byte];
                             stream_block: array[16, byte]; input: ptr byte;
                             output: ptr byte): cint {.importc, cdecl.}
proc mbedtls_aria_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
