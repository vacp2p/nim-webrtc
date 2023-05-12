#import strformat, os
#
## C include directory
#const root = currentSourcePath.parentDir
#const mbedtlsInclude = root/"mbedtls"/"include"
#const mbedtlsLibrary = root/"mbedtls"/"library"
#
#{.passc: fmt"-I{mbedtlsInclude} -I{mbedtlsLibrary}".}
#
import "asn1"
import "platform_time"
import "md"
import "cipher"
import "ctr_drbg"
import "rsa"
import "hash_info"
{.compile: "./mbedtls/library/pkcs5.c".}
# Generated @ 2023-05-11T11:19:12+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/pkcs5.h

{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
const
  MBEDTLS_ERR_PKCS5_BAD_INPUT_DATA* = -0x00002F80
  MBEDTLS_ERR_PKCS5_INVALID_FORMAT* = -0x00002F00
  MBEDTLS_ERR_PKCS5_FEATURE_UNAVAILABLE* = -0x00002E80
  MBEDTLS_ERR_PKCS5_PASSWORD_MISMATCH* = -0x00002E00
  MBEDTLS_PKCS5_DECRYPT* = 0
  MBEDTLS_PKCS5_ENCRYPT* = 1
proc mbedtls_pkcs5_pbes2*(pbe_params: ptr mbedtls_asn1_buf; mode: cint;
                          pwd: ptr byte; pwdlen: uint; data: ptr byte;
                          datalen: uint; output: ptr byte): cint {.importc,
    cdecl.}
proc mbedtls_pkcs5_pbkdf2_hmac_ext*(md_type: mbedtls_md_type_t;
                                    password: ptr byte; plen: uint;
                                    salt: ptr byte; slen: uint;
                                    iteration_count: cuint; key_length: uint32;
                                    output: ptr byte): cint {.importc, cdecl.}
proc mbedtls_pkcs5_pbkdf2_hmac*(ctx: ptr mbedtls_md_context_t;
                                password: ptr byte; plen: uint;
                                salt: ptr byte; slen: uint;
                                iteration_count: cuint; key_length: uint32;
                                output: ptr byte): cint {.importc, cdecl.}
proc mbedtls_pkcs5_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
