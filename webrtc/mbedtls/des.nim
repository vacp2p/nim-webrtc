#import strformat, os
#
## C include directory
#const root = currentSourcePath.parentDir
#const mbedtlsInclude = root/"mbedtls"/"include"
#const mbedtlsLibrary = root/"mbedtls"/"library"
#
#{.passc: fmt"-I{mbedtlsInclude} -I{mbedtlsLibrary}".}
#
import "private_access"
import "build_info"
import "mbedtls_config"
import "config_psa"
import "check_config"
import "platform_util"
import "platform_time"
{.compile: "./mbedtls/library/des.c".}
# Generated @ 2023-05-11T11:19:09+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/des.h

{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
const
  MBEDTLS_DES_ENCRYPT* = 1
  MBEDTLS_DES_DECRYPT* = 0
  MBEDTLS_ERR_DES_INVALID_INPUT_LENGTH* = -0x00000032
  MBEDTLS_DES_KEY_SIZE* = 8
type
  mbedtls_des_context* {.bycopy.} = object
    private_sk*: array[32, uint32]

  mbedtls_des3_context* {.bycopy.} = object
    private_sk*: array[96, uint32]

proc mbedtls_des_init*(ctx: ptr mbedtls_des_context) {.importc, cdecl.}
proc mbedtls_des_free*(ctx: ptr mbedtls_des_context) {.importc, cdecl.}
proc mbedtls_des3_init*(ctx: ptr mbedtls_des3_context) {.importc, cdecl.}
proc mbedtls_des3_free*(ctx: ptr mbedtls_des3_context) {.importc, cdecl.}
proc mbedtls_des_key_set_parity*(key: array[8, byte]) {.importc, cdecl.}
proc mbedtls_des_key_check_key_parity*(key: array[8, byte]): cint {.importc,
    cdecl.}
proc mbedtls_des_key_check_weak*(key: array[8, byte]): cint {.importc, cdecl.}
proc mbedtls_des_setkey_enc*(ctx: ptr mbedtls_des_context; key: array[8, byte]): cint {.
    importc, cdecl.}
proc mbedtls_des_setkey_dec*(ctx: ptr mbedtls_des_context; key: array[8, byte]): cint {.
    importc, cdecl.}
proc mbedtls_des3_set2key_enc*(ctx: ptr mbedtls_des3_context;
                               key: array[8 * typeof(8)(2), byte]): cint {.
    importc, cdecl.}
proc mbedtls_des3_set2key_dec*(ctx: ptr mbedtls_des3_context;
                               key: array[8 * typeof(8)(2), byte]): cint {.
    importc, cdecl.}
proc mbedtls_des3_set3key_enc*(ctx: ptr mbedtls_des3_context;
                               key: array[8 * typeof(8)(3), byte]): cint {.
    importc, cdecl.}
proc mbedtls_des3_set3key_dec*(ctx: ptr mbedtls_des3_context;
                               key: array[8 * typeof(8)(3), byte]): cint {.
    importc, cdecl.}
proc mbedtls_des_crypt_ecb*(ctx: ptr mbedtls_des_context;
                            input: array[8, byte]; output: array[8, byte]): cint {.
    importc, cdecl.}
proc mbedtls_des_crypt_cbc*(ctx: ptr mbedtls_des_context; mode: cint;
                            length: uint; iv: array[8, byte];
                            input: ptr byte; output: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_des3_crypt_ecb*(ctx: ptr mbedtls_des3_context;
                             input: array[8, byte]; output: array[8, byte]): cint {.
    importc, cdecl.}
proc mbedtls_des3_crypt_cbc*(ctx: ptr mbedtls_des3_context; mode: cint;
                             length: uint; iv: array[8, byte];
                             input: ptr byte; output: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_des_setkey*(SK: array[32, uint32]; key: array[8, byte]) {.
    importc, cdecl.}
proc mbedtls_des_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
