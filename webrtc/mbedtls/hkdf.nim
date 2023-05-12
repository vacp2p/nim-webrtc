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
import "md"
import "private_access"
import "platform_util"
import "platform_time"
{.compile: "./mbedtls/library/hkdf.c".}
# Generated @ 2023-05-11T11:19:10+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/hkdf.h

{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
const
  MBEDTLS_ERR_HKDF_BAD_INPUT_DATA* = -0x00005F80
proc mbedtls_hkdf*(md: ptr mbedtls_md_info_t; salt: ptr byte; salt_len: uint;
                   ikm: ptr byte; ikm_len: uint; info: ptr byte;
                   info_len: uint; okm: ptr byte; okm_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_hkdf_extract*(md: ptr mbedtls_md_info_t; salt: ptr byte;
                           salt_len: uint; ikm: ptr byte; ikm_len: uint;
                           prk: ptr byte): cint {.importc, cdecl.}
proc mbedtls_hkdf_expand*(md: ptr mbedtls_md_info_t; prk: ptr byte;
                          prk_len: uint; info: ptr byte; info_len: uint;
                          okm: ptr byte; okm_len: uint): cint {.importc, cdecl.}
{.pop.}
