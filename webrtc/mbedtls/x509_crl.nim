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
import "x509"
import "asn1"
import "platform_util"
import "platform_time"
import "bignum"
import "pk"
import "md"
import "rsa"
import "ecp"
import "ecdsa"
{.compile: "./mbedtls/library/x509_crl.c".}
# Generated @ 2023-05-11T11:19:15+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/x509_crl.h

{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
type
  mbedtls_x509_crl_entry* {.bycopy.} = object
    raw*: mbedtls_x509_buf
    serial*: mbedtls_x509_buf
    revocation_date*: mbedtls_x509_time
    entry_ext*: mbedtls_x509_buf
    next*: ptr mbedtls_x509_crl_entry

  mbedtls_x509_crl* {.bycopy.} = object
    raw*: mbedtls_x509_buf
    tbs*: mbedtls_x509_buf
    version*: cint
    sig_oid*: mbedtls_x509_buf
    issuer_raw*: mbedtls_x509_buf
    issuer*: mbedtls_x509_name
    this_update*: mbedtls_x509_time
    next_update*: mbedtls_x509_time
    entry*: mbedtls_x509_crl_entry
    crl_ext*: mbedtls_x509_buf
    private_sig_oid2*: mbedtls_x509_buf
    private_sig*: mbedtls_x509_buf
    private_sig_md*: mbedtls_md_type_t
    private_sig_pk*: mbedtls_pk_type_t
    private_sig_opts*: pointer
    next*: ptr mbedtls_x509_crl

proc mbedtls_x509_crl_parse_der*(chain: ptr mbedtls_x509_crl; buf: ptr byte;
                                 buflen: uint): cint {.importc, cdecl.}
proc mbedtls_x509_crl_parse*(chain: ptr mbedtls_x509_crl; buf: ptr byte;
                             buflen: uint): cint {.importc, cdecl.}
proc mbedtls_x509_crl_parse_file*(chain: ptr mbedtls_x509_crl; path: cstring): cint {.
    importc, cdecl.}
proc mbedtls_x509_crl_info*(buf: cstring; size: uint; prefix: cstring;
                            crl: ptr mbedtls_x509_crl): cint {.importc, cdecl.}
proc mbedtls_x509_crl_init*(crl: ptr mbedtls_x509_crl) {.importc, cdecl.}
proc mbedtls_x509_crl_free*(crl: ptr mbedtls_x509_crl) {.importc, cdecl.}
{.pop.}
