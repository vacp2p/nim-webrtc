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
{.compile: "./mbedtls/library/x509_csr.c".}
{.compile: "./mbedtls/library/x509write_csr.c".}
# Generated @ 2023-05-11T11:19:15+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/x509_csr.h

{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
type
  mbedtls_x509_csr* {.bycopy.} = object
    raw*: mbedtls_x509_buf
    cri*: mbedtls_x509_buf
    version*: cint
    subject_raw*: mbedtls_x509_buf
    subject*: mbedtls_x509_name
    pk*: mbedtls_pk_context
    key_usage*: cuint
    ns_cert_type*: byte
    subject_alt_names*: mbedtls_x509_sequence
    private_ext_types*: cint
    sig_oid*: mbedtls_x509_buf
    private_sig*: mbedtls_x509_buf
    private_sig_md*: mbedtls_md_type_t
    private_sig_pk*: mbedtls_pk_type_t
    private_sig_opts*: pointer

  mbedtls_x509write_csr* {.bycopy.} = object
    private_key*: ptr mbedtls_pk_context
    private_subject*: ptr mbedtls_asn1_named_data
    private_md_alg*: mbedtls_md_type_t
    private_extensions*: ptr mbedtls_asn1_named_data

  mbedtls_x509_san_list* {.bycopy.} = object
    node*: mbedtls_x509_subject_alternative_name
    next*: ptr mbedtls_x509_san_list

proc mbedtls_x509_csr_parse_der*(csr: ptr mbedtls_x509_csr; buf: ptr byte;
                                 buflen: uint): cint {.importc, cdecl.}
proc mbedtls_x509_csr_parse*(csr: ptr mbedtls_x509_csr; buf: ptr byte;
                             buflen: uint): cint {.importc, cdecl.}
proc mbedtls_x509_csr_parse_file*(csr: ptr mbedtls_x509_csr; path: cstring): cint {.
    importc, cdecl.}
proc mbedtls_x509_csr_info*(buf: cstring; size: uint; prefix: cstring;
                            csr: ptr mbedtls_x509_csr): cint {.importc, cdecl.}
proc mbedtls_x509_csr_init*(csr: ptr mbedtls_x509_csr) {.importc, cdecl.}
proc mbedtls_x509_csr_free*(csr: ptr mbedtls_x509_csr) {.importc, cdecl.}
proc mbedtls_x509write_csr_init*(ctx: ptr mbedtls_x509write_csr) {.importc,
    cdecl.}
proc mbedtls_x509write_csr_set_subject_name*(ctx: ptr mbedtls_x509write_csr;
    subject_name: cstring): cint {.importc, cdecl.}
proc mbedtls_x509write_csr_set_key*(ctx: ptr mbedtls_x509write_csr;
                                    key: ptr mbedtls_pk_context) {.importc,
    cdecl.}
proc mbedtls_x509write_csr_set_md_alg*(ctx: ptr mbedtls_x509write_csr;
                                       md_alg: mbedtls_md_type_t) {.importc,
    cdecl.}
proc mbedtls_x509write_csr_set_key_usage*(ctx: ptr mbedtls_x509write_csr;
    key_usage: byte): cint {.importc, cdecl.}
proc mbedtls_x509write_csr_set_subject_alternative_name*(
    ctx: ptr mbedtls_x509write_csr; san_list: ptr mbedtls_x509_san_list): cint {.
    importc, cdecl.}
proc mbedtls_x509write_csr_set_ns_cert_type*(ctx: ptr mbedtls_x509write_csr;
    ns_cert_type: byte): cint {.importc, cdecl.}
proc mbedtls_x509write_csr_set_extension*(ctx: ptr mbedtls_x509write_csr;
    oid: cstring; oid_len: uint; critical: cint; val: ptr byte; val_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_x509write_csr_free*(ctx: ptr mbedtls_x509write_csr) {.importc,
    cdecl.}
proc mbedtls_x509write_csr_der*(ctx: ptr mbedtls_x509write_csr; buf: ptr byte;
                                size: uint; f_rng: proc (a1: pointer;
    a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.importc,
    cdecl.}
proc mbedtls_x509write_csr_pem*(ctx: ptr mbedtls_x509write_csr; buf: ptr byte;
                                size: uint; f_rng: proc (a1: pointer;
    a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.importc,
    cdecl.}
{.pop.}
