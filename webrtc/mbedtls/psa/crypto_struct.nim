#import strformat, os
#
## C include directory
#const root = currentSourcePath.parentDir
#const mbedtlsInclude = root/"mbedtls"/"include"
#const mbedtlsLibrary = root/"mbedtls"/"library"
#
#{.passc: fmt"-I{mbedtlsInclude} -I{mbedtlsLibrary}".}
#
import "crypto_driver_contexts_primitives"
import "crypto_driver_common"
import "crypto_types"
import "crypto_platform"
import "crypto_values"
import "crypto_sizes"
import "crypto_builtin_primitives"
import "crypto_driver_contexts_composites"
import "crypto_builtin_composites"
import "crypto_driver_contexts_key_derivation"
{.compile: "./mbedtls/library/psa_crypto_client.c".}
# Generated @ 2023-05-12T13:12:44+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/psa/crypto_struct.h

# const 'PSA_HASH_OPERATION_INIT' has unsupported value '{ 0, { 0 } }'
# const 'PSA_CIPHER_OPERATION_INIT' has unsupported value '{ 0, 0, 0, 0, { 0 } }'
# const 'PSA_MAC_OPERATION_INIT' has unsupported value '{ 0, 0, 0, { 0 } }'
# const 'PSA_AEAD_OPERATION_INIT' has unsupported value '{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, { 0 } }'
# const 'PSA_KEY_DERIVATION_OPERATION_INIT' has unsupported value '{ 0, 0, 0, { 0 } }'
# const 'PSA_KEY_POLICY_INIT' has unsupported value '{ 0, 0, 0 }'
# const 'PSA_KEY_BITS_TOO_LARGE' has unsupported value '((psa_key_bits_t) -1)'
# const 'PSA_CORE_KEY_ATTRIBUTES_INIT' has unsupported value '{ PSA_KEY_TYPE_NONE, 0, PSA_KEY_LIFETIME_VOLATILE, MBEDTLS_SVC_KEY_ID_INIT, PSA_KEY_POLICY_INIT, 0 }'
# const 'PSA_KEY_ATTRIBUTES_INIT' has unsupported value '{ PSA_CORE_KEY_ATTRIBUTES_INIT, NULL, 0 }'
# const 'PSA_SIGN_HASH_INTERRUPTIBLE_OPERATION_INIT' has unsupported value '{ 0, { 0 }, 0, 0 }'
# const 'PSA_VERIFY_HASH_INTERRUPTIBLE_OPERATION_INIT' has unsupported value '{ 0, { 0 }, 0, 0 }'
{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.pragma: impcrypto_structHdr,
  header: "/home/lchenut/minnim/webrtc/mbedtls/include/psa/crypto_struct.h".}
{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
const
  PSA_MAX_KEY_BITS* = 0x0000FFF8
  MBEDTLS_PSA_KA_FLAG_HAS_SLOT_NUMBER* = (
    cast[psa_key_attributes_flag_t](0x00000001))
  MBEDTLS_PSA_KA_MASK_EXTERNAL_ONLY* = (MBEDTLS_PSA_KA_FLAG_HAS_SLOT_NUMBER or
      typeof(MBEDTLS_PSA_KA_FLAG_HAS_SLOT_NUMBER)(0))
  MBEDTLS_PSA_KA_MASK_DUAL_USE* = (0)

proc psa_hash_operation_init*(): psa_hash_operation_s {.importc, cdecl,
    impcrypto_structHdr.}
proc psa_cipher_operation_init*(): psa_cipher_operation_s {.importc, cdecl,
    impcrypto_structHdr.}
proc psa_mac_operation_init*(): psa_mac_operation_s {.importc, cdecl,
    impcrypto_structHdr.}
proc psa_aead_operation_init*(): psa_aead_operation_s {.importc, cdecl,
    impcrypto_structHdr.}
proc psa_key_derivation_operation_init*(): psa_key_derivation_s {.importc,
    cdecl, impcrypto_structHdr.}
proc psa_key_policy_init*(): psa_key_policy_s {.importc, cdecl,
    impcrypto_structHdr.}
proc psa_key_attributes_init*(): psa_key_attributes_s {.importc, cdecl,
    impcrypto_structHdr.}
proc psa_set_key_id*(attributes: ptr psa_key_attributes_t;
                     key: mbedtls_svc_key_id_t) {.importc, cdecl,
    impcrypto_structHdr.}
proc psa_get_key_id*(attributes: ptr psa_key_attributes_t): mbedtls_svc_key_id_t {.
    importc, cdecl, impcrypto_structHdr.}
proc psa_set_key_lifetime*(attributes: ptr psa_key_attributes_t;
                           lifetime: psa_key_lifetime_t) {.importc, cdecl,
    impcrypto_structHdr.}
proc psa_get_key_lifetime*(attributes: ptr psa_key_attributes_t): psa_key_lifetime_t {.
    importc, cdecl, impcrypto_structHdr.}
proc psa_extend_key_usage_flags*(usage_flags: ptr psa_key_usage_t) {.importc,
    cdecl, impcrypto_structHdr.}
proc psa_set_key_usage_flags*(attributes: ptr psa_key_attributes_t;
                              usage_flags: psa_key_usage_t) {.importc, cdecl,
    impcrypto_structHdr.}
proc psa_get_key_usage_flags*(attributes: ptr psa_key_attributes_t): psa_key_usage_t {.
    importc, cdecl, impcrypto_structHdr.}
proc psa_set_key_algorithm*(attributes: ptr psa_key_attributes_t;
                            alg: psa_algorithm_t) {.importc, cdecl,
    impcrypto_structHdr.}
proc psa_get_key_algorithm*(attributes: ptr psa_key_attributes_t): psa_algorithm_t {.
    importc, cdecl, impcrypto_structHdr.}
proc psa_set_key_domain_parameters*(attributes: ptr psa_key_attributes_t;
                                    `type`: psa_key_type_t; data: ptr uint8;
                                    data_length: uint): psa_status_t {.importc,
    cdecl, impcrypto_structHdr.}
proc psa_set_key_type*(attributes: ptr psa_key_attributes_t;
                       `type`: psa_key_type_t) {.importc, cdecl,
    impcrypto_structHdr.}
proc psa_get_key_type*(attributes: ptr psa_key_attributes_t): psa_key_type_t {.
    importc, cdecl, impcrypto_structHdr.}
proc psa_set_key_bits*(attributes: ptr psa_key_attributes_t; bits: uint) {.
    importc, cdecl, impcrypto_structHdr.}
proc psa_get_key_bits*(attributes: ptr psa_key_attributes_t): uint {.importc,
    cdecl, impcrypto_structHdr.}
proc psa_sign_hash_interruptible_operation_init*(): psa_sign_hash_interruptible_operation_s {.
    importc, cdecl, impcrypto_structHdr.}
proc psa_verify_hash_interruptible_operation_init*(): psa_verify_hash_interruptible_operation_s {.
    importc, cdecl, impcrypto_structHdr.}
{.pop.}
