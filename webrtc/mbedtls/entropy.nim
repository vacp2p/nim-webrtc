#import strformat, os
#
## C include directory
#const root = currentSourcePath.parentDir
#const mbedtlsInclude = root/"mbedtls"/"include"
#const mbedtlsLibrary = root/"mbedtls"/"library"
#
#{.passc: fmt"-I{mbedtlsInclude} -I{mbedtlsLibrary}".}
#
import "private_access"
import "build_info"
import "mbedtls_config"
import "config_psa"
import "check_config"
import "md"
import "platform_util"
import "platform_time"
{.compile: "./mbedtls/library/entropy.c".}
{.compile: "./mbedtls/library/entropy_poll.c".}
# Generated @ 2023-05-11T11:19:10+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/entropy.h

# const 'MBEDTLS_ENTROPY_MD' has unsupported value 'MBEDTLS_MD_SHA512'
# const 'MBEDTLS_ENTROPY_SOURCE_MANUAL' has unsupported value 'MBEDTLS_ENTROPY_MAX_SOURCES'
{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
const
  MBEDTLS_ENTROPY_BLOCK_SIZE* = 64
  MBEDTLS_ERR_ENTROPY_SOURCE_FAILED* = -0x0000003C
  MBEDTLS_ERR_ENTROPY_MAX_SOURCES* = -0x0000003E
  MBEDTLS_ERR_ENTROPY_NO_SOURCES_DEFINED* = -0x00000040
  MBEDTLS_ERR_ENTROPY_NO_STRONG_SOURCE* = -0x0000003D
  MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR* = -0x0000003F
  MBEDTLS_ENTROPY_MAX_SOURCES* = 20
  MBEDTLS_ENTROPY_MAX_GATHER* = 128
  MBEDTLS_ENTROPY_MAX_SEED_SIZE* = 1024
  MBEDTLS_ENTROPY_SOURCE_STRONG* = 1
  MBEDTLS_ENTROPY_SOURCE_WEAK* = 0
type
  mbedtls_entropy_f_source_ptr* = proc (data: pointer; output: ptr byte;
                                        len: uint; olen: ptr uint): cint {.cdecl.}
  mbedtls_entropy_source_state* {.bycopy.} = object
    private_f_source*: mbedtls_entropy_f_source_ptr
    private_p_source*: pointer
    private_size*: uint
    private_threshold*: uint
    private_strong*: cint

  mbedtls_entropy_context* {.bycopy.} = object
    private_accumulator_started*: cint
    private_accumulator*: mbedtls_md_context_t
    private_source_count*: cint
    private_source*: array[20, mbedtls_entropy_source_state]

proc mbedtls_platform_entropy_poll*(data: pointer; output: ptr byte;
                                    len: uint; olen: ptr uint): cint {.importc,
    cdecl.}
proc mbedtls_entropy_init*(ctx: ptr mbedtls_entropy_context) {.importc, cdecl.}
proc mbedtls_entropy_free*(ctx: ptr mbedtls_entropy_context) {.importc, cdecl.}
proc mbedtls_entropy_add_source*(ctx: ptr mbedtls_entropy_context;
                                 f_source: mbedtls_entropy_f_source_ptr;
                                 p_source: pointer; threshold: uint;
                                 strong: cint): cint {.importc, cdecl.}
proc mbedtls_entropy_gather*(ctx: ptr mbedtls_entropy_context): cint {.importc,
    cdecl.}
proc mbedtls_entropy_func*(data: pointer; output: ptr byte; len: uint): cint {.
    importc, cdecl.}
proc mbedtls_entropy_update_manual*(ctx: ptr mbedtls_entropy_context;
                                    data: ptr byte; len: uint): cint {.
    importc, cdecl.}
proc mbedtls_entropy_write_seed_file*(ctx: ptr mbedtls_entropy_context;
                                      path: cstring): cint {.importc, cdecl.}
proc mbedtls_entropy_update_seed_file*(ctx: ptr mbedtls_entropy_context;
                                       path: cstring): cint {.importc, cdecl.}
proc mbedtls_entropy_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
