#import strformat, os
#
## C include directory
#const root = currentSourcePath.parentDir
#const mbedtlsInclude = root/"mbedtls"/"include"
#const mbedtlsLibrary = root/"mbedtls"/"library"
#
#{.passc: fmt"-I{mbedtlsInclude} -I{mbedtlsLibrary}".}
#
# Generated @ 2023-05-11T11:19:09+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/compat-2.x.h

# const 'mbedtls_ctr_drbg_update_ret' has unsupported value 'mbedtls_ctr_drbg_update'
# const 'mbedtls_hmac_drbg_update_ret' has unsupported value 'mbedtls_hmac_drbg_update'
# const 'mbedtls_md5_starts_ret' has unsupported value 'mbedtls_md5_starts'
# const 'mbedtls_md5_update_ret' has unsupported value 'mbedtls_md5_update'
# const 'mbedtls_md5_finish_ret' has unsupported value 'mbedtls_md5_finish'
# const 'mbedtls_md5_ret' has unsupported value 'mbedtls_md5'
# const 'mbedtls_ripemd160_starts_ret' has unsupported value 'mbedtls_ripemd160_starts'
# const 'mbedtls_ripemd160_update_ret' has unsupported value 'mbedtls_ripemd160_update'
# const 'mbedtls_ripemd160_finish_ret' has unsupported value 'mbedtls_ripemd160_finish'
# const 'mbedtls_ripemd160_ret' has unsupported value 'mbedtls_ripemd160'
# const 'mbedtls_sha1_starts_ret' has unsupported value 'mbedtls_sha1_starts'
# const 'mbedtls_sha1_update_ret' has unsupported value 'mbedtls_sha1_update'
# const 'mbedtls_sha1_finish_ret' has unsupported value 'mbedtls_sha1_finish'
# const 'mbedtls_sha1_ret' has unsupported value 'mbedtls_sha1'
# const 'mbedtls_sha256_starts_ret' has unsupported value 'mbedtls_sha256_starts'
# const 'mbedtls_sha256_update_ret' has unsupported value 'mbedtls_sha256_update'
# const 'mbedtls_sha256_finish_ret' has unsupported value 'mbedtls_sha256_finish'
# const 'mbedtls_sha256_ret' has unsupported value 'mbedtls_sha256'
# const 'mbedtls_sha512_starts_ret' has unsupported value 'mbedtls_sha512_starts'
# const 'mbedtls_sha512_update_ret' has unsupported value 'mbedtls_sha512_update'
# const 'mbedtls_sha512_finish_ret' has unsupported value 'mbedtls_sha512_finish'
# const 'mbedtls_sha512_ret' has unsupported value 'mbedtls_sha512'
{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
{.pop.}
