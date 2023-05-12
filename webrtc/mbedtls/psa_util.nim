#import strformat, os
#
## C include directory
#const root = currentSourcePath.parentDir
#const mbedtlsInclude = root/"mbedtls"/"include"
#const mbedtlsLibrary = root/"mbedtls"/"library"
#
#{.passc: fmt"-I{mbedtlsInclude} -I{mbedtlsLibrary}".}
#
import "ctr_drbg"
import "pkcs5"
import "pkcs12"
import "psa/crypto_types"
{.compile: "./mbedtls/library/psa_util.c".}
# Generated @ 2023-05-11T11:19:13+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/psa_util.h

# proc 'mbedtls_psa_translate_cipher_type' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_psa_translate_cipher_mode' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_psa_translate_cipher_operation' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_psa_translate_md' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_psa_get_ecc_oid_from_id' skipped - static inline procs cannot work with '--noHeader | -H'
# const 'MBEDTLS_PSA_MAX_EC_PUBKEY_LENGTH' has unsupported value 'PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS)'
# const 'MBEDTLS_PSA_MAX_EC_KEY_PAIR_LENGTH' has unsupported value 'PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS)'
# const 'MBEDTLS_PSA_RANDOM_STATE' has unsupported value 'mbedtls_psa_random_state'
{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
type
  mbedtls_f_rng_t* = proc (p_rng: pointer; output: ptr byte; output_size: uint): cint {.
      cdecl.}
  mbedtls_psa_drbg_context_t* = mbedtls_ctr_drbg_context
  mbedtls_error_pair_t* {.bycopy.} = object
    psa_status*: psa_status_t
    mbedtls_error*: int16

var
  mbedtls_psa_get_random* {.importc.}: ptr mbedtls_f_rng_t
  mbedtls_psa_random_state* {.importc.}: ptr mbedtls_psa_drbg_context_t
  psa_to_lms_errors* {.importc.}: array[3, mbedtls_error_pair_t]
  psa_to_pk_rsa_errors* {.importc.}: array[8, mbedtls_error_pair_t]
proc psa_generic_status_to_mbedtls*(status: psa_status_t): cint {.importc, cdecl.}
proc psa_status_to_mbedtls*(status: psa_status_t;
                            local_translations: ptr mbedtls_error_pair_t;
                            local_errors_num: uint;
                            fallback_f: proc (a1: psa_status_t): cint {.cdecl.}): cint {.
    importc, cdecl.}
proc psa_pk_status_to_mbedtls*(status: psa_status_t): cint {.importc, cdecl.}
{.pop.}
