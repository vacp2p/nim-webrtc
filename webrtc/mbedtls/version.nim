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
{.compile: "./mbedtls/library/version.c".}
{.compile: "./mbedtls/library/version_features.c".}
# Generated @ 2023-05-11T11:19:15+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/version.h

{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
proc mbedtls_version_get_number*(): cuint {.importc, cdecl.}
proc mbedtls_version_get_string*(string: cstring) {.importc, cdecl.}
proc mbedtls_version_get_string_full*(string: cstring) {.importc, cdecl.}
proc mbedtls_version_check_feature*(feature: cstring): cint {.importc, cdecl.}
{.pop.}
