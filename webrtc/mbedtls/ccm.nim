#import strformat, os
#
## C include directory
#const root = currentSourcePath.parentDir
#const mbedtlsInclude = root/"mbedtls"/"include"
#const mbedtlsLibrary = root/"mbedtls"/"library"
#
#{.passc: fmt"-I{mbedtlsInclude} -I{mbedtlsLibrary}".}
#
# import "private_access"
# import "build_info"
# import "mbedtls_config"
# import "config_psa"
# import "check_config"
import "cipher"
# import "platform_util"
import "platform_time"
# Generated @ 2023-05-11T11:19:08+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/ccm.h

{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
const
  MBEDTLS_CCM_DECRYPT* = 0
  MBEDTLS_CCM_ENCRYPT* = 1
  MBEDTLS_CCM_STAR_DECRYPT* = 2
  MBEDTLS_CCM_STAR_ENCRYPT* = 3
  MBEDTLS_ERR_CCM_BAD_INPUT* = -0x0000000D
  MBEDTLS_ERR_CCM_AUTH_FAILED* = -0x0000000F
type
  mbedtls_ccm_context* {.bycopy.} = object
    private_y*: array[16, byte]
    private_ctr*: array[16, byte]
    private_cipher_ctx*: mbedtls_cipher_context_t
    private_plaintext_len*: uint
    private_add_len*: uint
    private_tag_len*: uint
    private_processed*: uint
    private_q*: byte
    private_mode*: byte
    private_state*: cint

proc mbedtls_ccm_init*(ctx: ptr mbedtls_ccm_context) {.importc, cdecl.}
proc mbedtls_ccm_setkey*(ctx: ptr mbedtls_ccm_context;
                         cipher: mbedtls_cipher_id_t; key: ptr byte;
                         keybits: cuint): cint {.importc, cdecl.}
proc mbedtls_ccm_free*(ctx: ptr mbedtls_ccm_context) {.importc, cdecl.}
proc mbedtls_ccm_encrypt_and_tag*(ctx: ptr mbedtls_ccm_context; length: uint;
                                  iv: ptr byte; iv_len: uint; ad: ptr byte;
                                  ad_len: uint; input: ptr byte;
                                  output: ptr byte; tag: ptr byte;
                                  tag_len: uint): cint {.importc, cdecl.}
proc mbedtls_ccm_star_encrypt_and_tag*(ctx: ptr mbedtls_ccm_context;
                                       length: uint; iv: ptr byte;
                                       iv_len: uint; ad: ptr byte;
                                       ad_len: uint; input: ptr byte;
                                       output: ptr byte; tag: ptr byte;
                                       tag_len: uint): cint {.importc, cdecl.}
proc mbedtls_ccm_auth_decrypt*(ctx: ptr mbedtls_ccm_context; length: uint;
                               iv: ptr byte; iv_len: uint; ad: ptr byte;
                               ad_len: uint; input: ptr byte;
                               output: ptr byte; tag: ptr byte;
                               tag_len: uint): cint {.importc, cdecl.}
proc mbedtls_ccm_star_auth_decrypt*(ctx: ptr mbedtls_ccm_context; length: uint;
                                    iv: ptr byte; iv_len: uint;
                                    ad: ptr byte; ad_len: uint;
                                    input: ptr byte; output: ptr byte;
                                    tag: ptr byte; tag_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_ccm_starts*(ctx: ptr mbedtls_ccm_context; mode: cint;
                         iv: ptr byte; iv_len: uint): cint {.importc, cdecl.}
proc mbedtls_ccm_set_lengths*(ctx: ptr mbedtls_ccm_context; total_ad_len: uint;
                              plaintext_len: uint; tag_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_ccm_update_ad*(ctx: ptr mbedtls_ccm_context; ad: ptr byte;
                            ad_len: uint): cint {.importc, cdecl.}
proc mbedtls_ccm_update*(ctx: ptr mbedtls_ccm_context; input: ptr byte;
                         input_len: uint; output: ptr byte; output_size: uint;
                         output_len: ptr uint): cint {.importc, cdecl.}
proc mbedtls_ccm_finish*(ctx: ptr mbedtls_ccm_context; tag: ptr byte;
                         tag_len: uint): cint {.importc, cdecl.}
proc mbedtls_ccm_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
