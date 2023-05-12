#import strformat, os
#
## C include directory
#const root = currentSourcePath.parentDir
#const mbedtlsInclude = root/"mbedtls"/"include"
#const mbedtlsLibrary = root/"mbedtls"/"library"
#
#{.passc: fmt"-I{mbedtlsInclude} -I{mbedtlsLibrary}".}
#
type tm {.importc: "struct tm", header: "<time.h>".} = object
# import "build_info"
# import "mbedtls_config"
# import "config_psa"
# import "check_config"
import "platform_time"
# {.compile: "./mbedtls/library/platform_util.c".}
# Generated @ 2023-05-11T11:19:12+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/platform_util.h

# const 'MBEDTLS_CHECK_RETURN' has unsupported value '__attribute__((__warn_unused_result__))'
# const 'MBEDTLS_CHECK_RETURN_CRITICAL' has unsupported value 'MBEDTLS_CHECK_RETURN'
{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
proc mbedtls_platform_zeroize*(buf: pointer; len: uint) {.importc, cdecl.}
proc mbedtls_platform_gmtime_r*(tt: ptr mbedtls_time_t; tm_buf: ptr tm): ptr tm {.
    importc, cdecl.}
{.pop.}
