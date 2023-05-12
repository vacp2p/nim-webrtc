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
{.compile: "./mbedtls/library/timing.c".}
# Generated @ 2023-05-11T11:19:15+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/timing.h

{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
type
  mbedtls_timing_hr_time* {.bycopy.} = object
    private_opaque*: array[4, uint64]

  mbedtls_timing_delay_context* {.bycopy.} = object
    private_timer*: mbedtls_timing_hr_time
    private_int_ms*: uint32
    private_fin_ms*: uint32

proc mbedtls_timing_get_timer*(val: ptr mbedtls_timing_hr_time; reset: cint): culong {.
    importc, cdecl.}
proc mbedtls_timing_set_delay*(data: pointer; int_ms: uint32; fin_ms: uint32) {.
    importc, cdecl.}
proc mbedtls_timing_get_delay*(data: pointer): cint {.importc, cdecl.}
proc mbedtls_timing_get_final_delay*(data: ptr mbedtls_timing_delay_context): uint32 {.
    importc, cdecl.}
{.pop.}
