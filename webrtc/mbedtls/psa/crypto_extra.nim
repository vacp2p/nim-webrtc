#import strformat, os
#
## C include directory
#const root = currentSourcePath.parentDir
#const mbedtlsInclude = root/"mbedtls"/"include"
#const mbedtlsLibrary = root/"mbedtls"/"library"
#
#{.passc: fmt"-I{mbedtlsInclude} -I{mbedtlsLibrary}".}
#
# Generated @ 2023-05-12T13:12:43+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/psa/crypto_extra.h

# const 'PSA_ALG_DSA_DETERMINISTIC_FLAG' has unsupported value 'PSA_ALG_ECDSA_DETERMINISTIC_FLAG'
# const 'PSA_PAKE_CIPHER_SUITE_INIT' has unsupported value '{ PSA_ALG_NONE, 0, 0, 0, PSA_ALG_NONE }'
# const 'PSA_PAKE_OPERATION_INIT' has unsupported value '{ 0, PSA_ALG_NONE, 0, PSA_PAKE_OPERATION_STAGE_SETUP, { 0 }, { { 0 } } }'
{.push hint[ConvFromXtoItselfNotNeeded]: off.}
{.pragma: impcrypto_extraHdr,
  header: "/home/lchenut/minnim/webrtc/mbedtls/include/psa/crypto_extra.h".}
{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
{.pop.}
