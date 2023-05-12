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
import "aes"
import "platform_util"
import "platform_time"
import "entropy"
import "md"
{.compile: "./mbedtls/library/ctr_drbg.c".}
# Generated @ 2023-05-11T11:19:09+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/ctr_drbg.h

{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
const
  MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED* = -0x00000034
  MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG* = -0x00000036
  MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG* = -0x00000038
  MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR* = -0x0000003A
  MBEDTLS_CTR_DRBG_BLOCKSIZE* = 16
  MBEDTLS_CTR_DRBG_KEYSIZE* = 32
  MBEDTLS_CTR_DRBG_KEYBITS* = (
    MBEDTLS_CTR_DRBG_KEYSIZE * typeof(MBEDTLS_CTR_DRBG_KEYSIZE)(8))
  MBEDTLS_CTR_DRBG_SEEDLEN* = (MBEDTLS_CTR_DRBG_KEYSIZE +
      typeof(MBEDTLS_CTR_DRBG_KEYSIZE)(MBEDTLS_CTR_DRBG_BLOCKSIZE))
  MBEDTLS_CTR_DRBG_ENTROPY_LEN* = 48
  MBEDTLS_CTR_DRBG_RESEED_INTERVAL* = 10000
  MBEDTLS_CTR_DRBG_MAX_INPUT* = 256
  MBEDTLS_CTR_DRBG_MAX_REQUEST* = 1024
  MBEDTLS_CTR_DRBG_MAX_SEED_INPUT* = 384
  MBEDTLS_CTR_DRBG_PR_OFF* = 0
  MBEDTLS_CTR_DRBG_PR_ON* = 1
  MBEDTLS_CTR_DRBG_ENTROPY_NONCE_LEN* = 0
type
  mbedtls_ctr_drbg_context* {.bycopy.} = object
    private_counter*: array[16, byte]
    private_reseed_counter*: cint
    private_prediction_resistance*: cint
    private_entropy_len*: uint
    private_reseed_interval*: cint
    private_aes_ctx*: mbedtls_aes_context
    private_f_entropy*: proc (a1: pointer; a2: ptr byte; a3: uint): cint {.
        cdecl.}
    private_p_entropy*: pointer

proc mbedtls_ctr_drbg_init*(ctx: ptr mbedtls_ctr_drbg_context) {.importc, cdecl.}
proc mbedtls_ctr_drbg_seed*(ctx: ptr mbedtls_ctr_drbg_context; f_entropy: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_entropy: pointer;
                            custom: ptr byte; len: uint): cint {.importc,
    cdecl.}
proc mbedtls_ctr_drbg_free*(ctx: ptr mbedtls_ctr_drbg_context) {.importc, cdecl.}
proc mbedtls_ctr_drbg_set_prediction_resistance*(
    ctx: ptr mbedtls_ctr_drbg_context; resistance: cint) {.importc, cdecl.}
proc mbedtls_ctr_drbg_set_entropy_len*(ctx: ptr mbedtls_ctr_drbg_context;
                                       len: uint) {.importc, cdecl.}
proc mbedtls_ctr_drbg_set_nonce_len*(ctx: ptr mbedtls_ctr_drbg_context;
                                     len: uint): cint {.importc, cdecl.}
proc mbedtls_ctr_drbg_set_reseed_interval*(ctx: ptr mbedtls_ctr_drbg_context;
    interval: cint) {.importc, cdecl.}
proc mbedtls_ctr_drbg_reseed*(ctx: ptr mbedtls_ctr_drbg_context;
                              additional: ptr byte; len: uint): cint {.
    importc, cdecl.}
proc mbedtls_ctr_drbg_update*(ctx: ptr mbedtls_ctr_drbg_context;
                              additional: ptr byte; add_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_ctr_drbg_random_with_add*(p_rng: pointer; output: ptr byte;
                                       output_len: uint; additional: ptr byte;
                                       add_len: uint): cint {.importc, cdecl.}
proc mbedtls_ctr_drbg_random*(p_rng: pointer; output: ptr byte;
                              output_len: uint): cint {.importc, cdecl.}
proc mbedtls_ctr_drbg_write_seed_file*(ctx: ptr mbedtls_ctr_drbg_context;
                                       path: cstring): cint {.importc, cdecl.}
proc mbedtls_ctr_drbg_update_seed_file*(ctx: ptr mbedtls_ctr_drbg_context;
                                        path: cstring): cint {.importc, cdecl.}
proc mbedtls_ctr_drbg_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
