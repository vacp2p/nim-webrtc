#import strformat, os
#
## C include directory
#const root = currentSourcePath.parentDir
#const mbedtlsInclude = root/"mbedtls"/"include"
#const mbedtlsLibrary = root/"mbedtls"/"library"
#
#{.passc: fmt"-I{mbedtlsInclude} -I{mbedtlsLibrary}".}
#
import "build_info"
import "mbedtls_config"
import "config_psa"
import "check_config"
{.compile: "./mbedtls/library/error.c".}
# Generated @ 2023-05-11T11:19:10+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/error.h

# proc 'mbedtls_error_add' skipped - static inline procs cannot work with '--noHeader | -H'
{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
const
  MBEDTLS_ERR_ERROR_GENERIC_ERROR* = -0x00000001
  MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED* = -0x0000006E
  MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED* = -0x00000070
  MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED* = -0x00000072
proc mbedtls_strerror*(errnum: cint; buffer: cstring; buflen: uint) {.importc,
    cdecl.}
proc mbedtls_high_level_strerr*(error_code: cint): cstring {.importc, cdecl.}
proc mbedtls_low_level_strerr*(error_code: cint): cstring {.importc, cdecl.}
{.pop.}
