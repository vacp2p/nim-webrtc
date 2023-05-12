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
import "cipher"
import "platform_util"
import "platform_time"
#{.compile: "./mbedtls/library/gcm.c".}
# Generated @ 2023-05-11T11:19:10+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/gcm.h

{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
const
  MBEDTLS_GCM_ENCRYPT* = 1
  MBEDTLS_GCM_DECRYPT* = 0
  MBEDTLS_ERR_GCM_AUTH_FAILED* = -0x00000012
  MBEDTLS_ERR_GCM_BAD_INPUT* = -0x00000014
  MBEDTLS_ERR_GCM_BUFFER_TOO_SMALL* = -0x00000016
type
  mbedtls_gcm_context* {.bycopy.} = object
    private_cipher_ctx*: mbedtls_cipher_context_t
    private_HL*: array[16, uint64]
    private_HH*: array[16, uint64]
    private_len*: uint64
    private_add_len*: uint64
    private_base_ectr*: array[16, byte]
    private_y*: array[16, byte]
    private_buf*: array[16, byte]
    private_mode*: cint

proc mbedtls_gcm_init*(ctx: ptr mbedtls_gcm_context) {.importc, cdecl.}
proc mbedtls_gcm_setkey*(ctx: ptr mbedtls_gcm_context;
                         cipher: mbedtls_cipher_id_t; key: ptr byte;
                         keybits: cuint): cint {.importc, cdecl.}
proc mbedtls_gcm_crypt_and_tag*(ctx: ptr mbedtls_gcm_context; mode: cint;
                                length: uint; iv: ptr byte; iv_len: uint;
                                add: ptr byte; add_len: uint;
                                input: ptr byte; output: ptr byte;
                                tag_len: uint; tag: ptr byte): cint {.importc,
    cdecl.}
proc mbedtls_gcm_auth_decrypt*(ctx: ptr mbedtls_gcm_context; length: uint;
                               iv: ptr byte; iv_len: uint; add: ptr byte;
                               add_len: uint; tag: ptr byte; tag_len: uint;
                               input: ptr byte; output: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_gcm_starts*(ctx: ptr mbedtls_gcm_context; mode: cint;
                         iv: ptr byte; iv_len: uint): cint {.importc, cdecl.}
proc mbedtls_gcm_update_ad*(ctx: ptr mbedtls_gcm_context; add: ptr byte;
                            add_len: uint): cint {.importc, cdecl.}
proc mbedtls_gcm_update*(ctx: ptr mbedtls_gcm_context; input: ptr byte;
                         input_length: uint; output: ptr byte;
                         output_size: uint; output_length: ptr uint): cint {.
    importc, cdecl.}
proc mbedtls_gcm_finish*(ctx: ptr mbedtls_gcm_context; output: ptr byte;
                         output_size: uint; output_length: ptr uint;
                         tag: ptr byte; tag_len: uint): cint {.importc, cdecl.}
proc mbedtls_gcm_free*(ctx: ptr mbedtls_gcm_context) {.importc, cdecl.}
proc mbedtls_gcm_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
