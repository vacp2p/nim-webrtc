#import strformat, os
#
## C include directory
#const root = currentSourcePath.parentDir
#const mbedtlsInclude = root/"mbedtls"/"include"
#const mbedtlsLibrary = root/"mbedtls"/"library"
#
#{.passc: fmt"-I{mbedtlsInclude} -I{mbedtlsLibrary}".}
#
import "asn1"
import "platform_time"
import "bignum"
{.compile: "./mbedtls/library/asn1write.c".}
# Generated @ 2023-05-11T11:19:07+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/asn1write.h

{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
proc mbedtls_asn1_write_len*(p: ptr ptr byte; start: ptr byte; len: uint): cint {.
    importc, cdecl.}
proc mbedtls_asn1_write_tag*(p: ptr ptr byte; start: ptr byte; tag: byte): cint {.
    importc, cdecl.}
proc mbedtls_asn1_write_raw_buffer*(p: ptr ptr byte; start: ptr byte;
                                    buf: ptr byte; size: uint): cint {.
    importc, cdecl.}
proc mbedtls_asn1_write_mpi*(p: ptr ptr byte; start: ptr byte;
                             X: ptr mbedtls_mpi): cint {.importc, cdecl.}
proc mbedtls_asn1_write_null*(p: ptr ptr byte; start: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_asn1_write_oid*(p: ptr ptr byte; start: ptr byte; oid: cstring;
                             oid_len: uint): cint {.importc, cdecl.}
proc mbedtls_asn1_write_algorithm_identifier*(p: ptr ptr byte;
    start: ptr byte; oid: cstring; oid_len: uint; par_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_asn1_write_bool*(p: ptr ptr byte; start: ptr byte;
                              boolean: cint): cint {.importc, cdecl.}
proc mbedtls_asn1_write_int*(p: ptr ptr byte; start: ptr byte; val: cint): cint {.
    importc, cdecl.}
proc mbedtls_asn1_write_enum*(p: ptr ptr byte; start: ptr byte; val: cint): cint {.
    importc, cdecl.}
proc mbedtls_asn1_write_tagged_string*(p: ptr ptr byte; start: ptr byte;
                                       tag: cint; text: cstring; text_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_asn1_write_printable_string*(p: ptr ptr byte; start: ptr byte;
    text: cstring; text_len: uint): cint {.importc, cdecl.}
proc mbedtls_asn1_write_utf8_string*(p: ptr ptr byte; start: ptr byte;
                                     text: cstring; text_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_asn1_write_ia5_string*(p: ptr ptr byte; start: ptr byte;
                                    text: cstring; text_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_asn1_write_bitstring*(p: ptr ptr byte; start: ptr byte;
                                   buf: ptr byte; bits: uint): cint {.importc,
    cdecl.}
proc mbedtls_asn1_write_named_bitstring*(p: ptr ptr byte; start: ptr byte;
    buf: ptr byte; bits: uint): cint {.importc, cdecl.}
proc mbedtls_asn1_write_octet_string*(p: ptr ptr byte; start: ptr byte;
                                      buf: ptr byte; size: uint): cint {.
    importc, cdecl.}
proc mbedtls_asn1_store_named_data*(list: ptr ptr mbedtls_asn1_named_data;
                                    oid: cstring; oid_len: uint;
                                    val: ptr byte; val_len: uint): ptr mbedtls_asn1_named_data {.
    importc, cdecl.}
{.pop.}
