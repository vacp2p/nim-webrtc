#import strformat, os
#
## C include directory
#const root = currentSourcePath.parentDir
#const mbedtlsInclude = root/"mbedtls"/"include"
#const mbedtlsLibrary = root/"mbedtls"/"library"
#
#{.passc: fmt"-I{mbedtlsInclude} -I{mbedtlsLibrary}".}
#
# import "build_info"
# import "mbedtls_config"
# import "config_psa"
# import "check_config"
import "constant_time"
{.compile: "./mbedtls/library/base64.c".}
# Generated @ 2023-05-11T11:19:07+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/base64.h

{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
const
  MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL* = -0x0000002A
  MBEDTLS_ERR_BASE64_INVALID_CHARACTER* = -0x0000002C
proc mbedtls_base64_encode*(dst: ptr byte; dlen: uint; olen: ptr uint;
                            src: ptr byte; slen: uint): cint {.importc, cdecl.}
proc mbedtls_base64_decode*(dst: ptr byte; dlen: uint; olen: ptr uint;
                            src: ptr byte; slen: uint): cint {.importc, cdecl.}
proc mbedtls_base64_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
