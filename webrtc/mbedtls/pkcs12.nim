#import strformat, os
#
## C include directory
#const root = currentSourcePath.parentDir
#const mbedtlsInclude = root/"mbedtls"/"include"
#const mbedtlsLibrary = root/"mbedtls"/"library"
#
#{.passc: fmt"-I{mbedtlsInclude} -I{mbedtlsLibrary}".}
#
import "md"
import "platform_time"
import "cipher"
import "asn1"
import "ctr_drbg"
import "hash_info"
{.compile: "./mbedtls/library/pkcs12.c".}
# Generated @ 2023-05-11T11:19:12+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/pkcs12.h

{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
const
  MBEDTLS_ERR_PKCS12_BAD_INPUT_DATA* = -0x00001F80
  MBEDTLS_ERR_PKCS12_FEATURE_UNAVAILABLE* = -0x00001F00
  MBEDTLS_ERR_PKCS12_PBE_INVALID_FORMAT* = -0x00001E80
  MBEDTLS_ERR_PKCS12_PASSWORD_MISMATCH* = -0x00001E00
  MBEDTLS_PKCS12_DERIVE_KEY* = 1
  MBEDTLS_PKCS12_DERIVE_IV* = 2
  MBEDTLS_PKCS12_DERIVE_MAC_KEY* = 3
  MBEDTLS_PKCS12_PBE_DECRYPT* = 0
  MBEDTLS_PKCS12_PBE_ENCRYPT* = 1
proc mbedtls_pkcs12_pbe*(pbe_params: ptr mbedtls_asn1_buf; mode: cint;
                         cipher_type: mbedtls_cipher_type_t;
                         md_type: mbedtls_md_type_t; pwd: ptr byte;
                         pwdlen: uint; input: ptr byte; len: uint;
                         output: ptr byte): cint {.importc, cdecl.}
proc mbedtls_pkcs12_derivation*(data: ptr byte; datalen: uint;
                                pwd: ptr byte; pwdlen: uint; salt: ptr byte;
                                saltlen: uint; mbedtls_md: mbedtls_md_type_t;
                                id: cint; iterations: cint): cint {.importc,
    cdecl.}
{.pop.}
