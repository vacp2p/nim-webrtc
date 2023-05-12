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
import "platform_time"
{.compile: "./mbedtls/library/platform.c".}
# Generated @ 2023-05-11T11:19:12+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/platform.h

# const 'MBEDTLS_PLATFORM_STD_SNPRINTF' has unsupported value 'snprintf'
# const 'MBEDTLS_PLATFORM_STD_VSNPRINTF' has unsupported value 'vsnprintf'
# const 'MBEDTLS_PLATFORM_STD_PRINTF' has unsupported value 'printf'
# const 'MBEDTLS_PLATFORM_STD_FPRINTF' has unsupported value 'fprintf'
# const 'MBEDTLS_PLATFORM_STD_CALLOC' has unsupported value 'calloc'
# const 'MBEDTLS_PLATFORM_STD_FREE' has unsupported value 'free'
# const 'MBEDTLS_PLATFORM_STD_SETBUF' has unsupported value 'setbuf'
# const 'MBEDTLS_PLATFORM_STD_EXIT' has unsupported value 'exit'
# const 'MBEDTLS_PLATFORM_STD_TIME' has unsupported value 'time'
# const 'MBEDTLS_PLATFORM_STD_EXIT_SUCCESS' has unsupported value 'EXIT_SUCCESS'
# const 'MBEDTLS_PLATFORM_STD_EXIT_FAILURE' has unsupported value 'EXIT_FAILURE'
# const 'MBEDTLS_PLATFORM_STD_NV_SEED_READ' has unsupported value 'mbedtls_platform_std_nv_seed_read'
# const 'MBEDTLS_PLATFORM_STD_NV_SEED_WRITE' has unsupported value 'mbedtls_platform_std_nv_seed_write'
# const 'mbedtls_free' has unsupported value 'free'
# const 'mbedtls_calloc' has unsupported value 'calloc'
# const 'mbedtls_fprintf' has unsupported value 'fprintf'
# const 'mbedtls_printf' has unsupported value 'printf'
# const 'mbedtls_snprintf' has unsupported value 'MBEDTLS_PLATFORM_STD_SNPRINTF'
# const 'mbedtls_vsnprintf' has unsupported value 'vsnprintf'
# const 'mbedtls_setbuf' has unsupported value 'setbuf'
# const 'mbedtls_exit' has unsupported value 'exit'
# const 'MBEDTLS_EXIT_SUCCESS' has unsupported value 'MBEDTLS_PLATFORM_STD_EXIT_SUCCESS'
# const 'MBEDTLS_EXIT_FAILURE' has unsupported value 'MBEDTLS_PLATFORM_STD_EXIT_FAILURE'
{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
const
  MBEDTLS_PLATFORM_STD_NV_SEED_FILE* = "seedfile"
type
  mbedtls_platform_context* {.bycopy.} = object
    private_dummy*: cchar

proc mbedtls_platform_setup*(ctx: ptr mbedtls_platform_context): cint {.importc,
    cdecl.}
proc mbedtls_platform_teardown*(ctx: ptr mbedtls_platform_context) {.importc,
    cdecl.}
{.pop.}
