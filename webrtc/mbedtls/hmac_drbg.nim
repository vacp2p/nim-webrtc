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
import "md"
import "platform_util"
import "platform_time"
{.compile: "./mbedtls/library/hmac_drbg.c".}
# Generated @ 2023-05-11T11:19:11+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/hmac_drbg.h

{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
const
  MBEDTLS_ERR_HMAC_DRBG_REQUEST_TOO_BIG* = -0x00000003
  MBEDTLS_ERR_HMAC_DRBG_INPUT_TOO_BIG* = -0x00000005
  MBEDTLS_ERR_HMAC_DRBG_FILE_IO_ERROR* = -0x00000007
  MBEDTLS_ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED* = -0x00000009
  MBEDTLS_HMAC_DRBG_RESEED_INTERVAL* = 10000
  MBEDTLS_HMAC_DRBG_MAX_INPUT* = 256
  MBEDTLS_HMAC_DRBG_MAX_REQUEST* = 1024
  MBEDTLS_HMAC_DRBG_MAX_SEED_INPUT* = 384
  MBEDTLS_HMAC_DRBG_PR_OFF* = 0
  MBEDTLS_HMAC_DRBG_PR_ON* = 1
type
  mbedtls_hmac_drbg_context* {.bycopy.} = object
    private_md_ctx*: mbedtls_md_context_t
    private_V*: array[64, byte]
    private_reseed_counter*: cint
    private_entropy_len*: uint
    private_prediction_resistance*: cint
    private_reseed_interval*: cint
    private_f_entropy*: proc (a1: pointer; a2: ptr byte; a3: uint): cint {.
        cdecl.}
    private_p_entropy*: pointer

proc mbedtls_hmac_drbg_init*(ctx: ptr mbedtls_hmac_drbg_context) {.importc,
    cdecl.}
proc mbedtls_hmac_drbg_seed*(ctx: ptr mbedtls_hmac_drbg_context;
                             md_info: ptr mbedtls_md_info_t; f_entropy: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_entropy: pointer;
                             custom: ptr byte; len: uint): cint {.importc,
    cdecl.}
proc mbedtls_hmac_drbg_seed_buf*(ctx: ptr mbedtls_hmac_drbg_context;
                                 md_info: ptr mbedtls_md_info_t;
                                 data: ptr byte; data_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_hmac_drbg_set_prediction_resistance*(
    ctx: ptr mbedtls_hmac_drbg_context; resistance: cint) {.importc, cdecl.}
proc mbedtls_hmac_drbg_set_entropy_len*(ctx: ptr mbedtls_hmac_drbg_context;
                                        len: uint) {.importc, cdecl.}
proc mbedtls_hmac_drbg_set_reseed_interval*(ctx: ptr mbedtls_hmac_drbg_context;
    interval: cint) {.importc, cdecl.}
proc mbedtls_hmac_drbg_update*(ctx: ptr mbedtls_hmac_drbg_context;
                               additional: ptr byte; add_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_hmac_drbg_reseed*(ctx: ptr mbedtls_hmac_drbg_context;
                               additional: ptr byte; len: uint): cint {.
    importc, cdecl.}
proc mbedtls_hmac_drbg_random_with_add*(p_rng: pointer; output: ptr byte;
                                        output_len: uint;
                                        additional: ptr byte; add_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_hmac_drbg_random*(p_rng: pointer; output: ptr byte; out_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_hmac_drbg_free*(ctx: ptr mbedtls_hmac_drbg_context) {.importc,
    cdecl.}
proc mbedtls_hmac_drbg_write_seed_file*(ctx: ptr mbedtls_hmac_drbg_context;
                                        path: cstring): cint {.importc, cdecl.}
proc mbedtls_hmac_drbg_update_seed_file*(ctx: ptr mbedtls_hmac_drbg_context;
    path: cstring): cint {.importc, cdecl.}
proc mbedtls_hmac_drbg_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
