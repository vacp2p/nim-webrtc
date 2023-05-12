#import strformat, os
#
## C include directory
#const root = currentSourcePath.parentDir
#const mbedtlsInclude = root/"mbedtls"/"include"
#const mbedtlsLibrary = root/"mbedtls"/"library"
#
#{.passc: fmt"-I{mbedtlsInclude} -I{mbedtlsLibrary}".}
#
import "cipher"
import "platform_time"
{.compile: "./mbedtls/library/cmac.c".}
# Generated @ 2023-05-11T11:19:09+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/cmac.h

{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
const
  MBEDTLS_AES_BLOCK_SIZE* = 16
  MBEDTLS_DES3_BLOCK_SIZE* = 8
  MBEDTLS_CIPHER_BLKSIZE_MAX* = 16
type
  mbedtls_cmac_context_t* {.bycopy.} = object
    private_state*: array[16, byte]
    private_unprocessed_block*: array[16, byte]
    private_unprocessed_len*: uint

proc mbedtls_cipher_cmac_starts*(ctx: ptr mbedtls_cipher_context_t;
                                 key: ptr byte; keybits: uint): cint {.
    importc, cdecl.}
proc mbedtls_cipher_cmac_update*(ctx: ptr mbedtls_cipher_context_t;
                                 input: ptr byte; ilen: uint): cint {.importc,
    cdecl.}
proc mbedtls_cipher_cmac_finish*(ctx: ptr mbedtls_cipher_context_t;
                                 output: ptr byte): cint {.importc, cdecl.}
proc mbedtls_cipher_cmac_reset*(ctx: ptr mbedtls_cipher_context_t): cint {.
    importc, cdecl.}
proc mbedtls_cipher_cmac*(cipher_info: ptr mbedtls_cipher_info_t;
                          key: ptr byte; keylen: uint; input: ptr byte;
                          ilen: uint; output: ptr byte): cint {.importc, cdecl.}
proc mbedtls_aes_cmac_prf_128*(key: ptr byte; key_len: uint;
                               input: ptr byte; in_len: uint;
                               output: array[16, byte]): cint {.importc, cdecl.}
proc mbedtls_cmac_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
