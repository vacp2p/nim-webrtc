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
{.compile: "./mbedtls/library/camellia.c".}
# Generated @ 2023-05-11T11:19:08+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/camellia.h

{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
const
  MBEDTLS_CAMELLIA_ENCRYPT* = 1
  MBEDTLS_CAMELLIA_DECRYPT* = 0
  MBEDTLS_ERR_CAMELLIA_BAD_INPUT_DATA* = -0x00000024
  MBEDTLS_ERR_CAMELLIA_INVALID_INPUT_LENGTH* = -0x00000026
type
  mbedtls_camellia_context* {.bycopy.} = object
    private_nr*: cint
    private_rk*: array[68, uint32]

proc mbedtls_camellia_init*(ctx: ptr mbedtls_camellia_context) {.importc, cdecl.}
proc mbedtls_camellia_free*(ctx: ptr mbedtls_camellia_context) {.importc, cdecl.}
proc mbedtls_camellia_setkey_enc*(ctx: ptr mbedtls_camellia_context;
                                  key: ptr byte; keybits: cuint): cint {.
    importc, cdecl.}
proc mbedtls_camellia_setkey_dec*(ctx: ptr mbedtls_camellia_context;
                                  key: ptr byte; keybits: cuint): cint {.
    importc, cdecl.}
proc mbedtls_camellia_crypt_ecb*(ctx: ptr mbedtls_camellia_context; mode: cint;
                                 input: array[16, byte];
                                 output: array[16, byte]): cint {.importc,
    cdecl.}
proc mbedtls_camellia_crypt_cbc*(ctx: ptr mbedtls_camellia_context; mode: cint;
                                 length: uint; iv: array[16, byte];
                                 input: ptr byte; output: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_camellia_crypt_cfb128*(ctx: ptr mbedtls_camellia_context;
                                    mode: cint; length: uint; iv_off: ptr uint;
                                    iv: array[16, byte]; input: ptr byte;
                                    output: ptr byte): cint {.importc, cdecl.}
proc mbedtls_camellia_crypt_ctr*(ctx: ptr mbedtls_camellia_context;
                                 length: uint; nc_off: ptr uint;
                                 nonce_counter: array[16, byte];
                                 stream_block: array[16, byte];
                                 input: ptr byte; output: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_camellia_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
