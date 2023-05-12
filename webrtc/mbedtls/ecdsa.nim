#import strformat, os
#
## C include directory
#const root = currentSourcePath.parentDir
#const mbedtlsInclude = root/"mbedtls"/"include"
#const mbedtlsLibrary = root/"mbedtls"/"library"
#
#{.passc: fmt"-I{mbedtlsInclude} -I{mbedtlsLibrary}".}
#
import "ecp"
import "bignum"
import "md"
import "platform_time"
import "hmac_drbg"
import "asn1"
import "asn1write"
{.compile: "./mbedtls/library/ecdsa.c".}
# Generated @ 2023-05-11T11:19:10+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/ecdsa.h

# const 'MBEDTLS_ECDSA_MAX_LEN' has unsupported value 'MBEDTLS_ECDSA_MAX_SIG_LEN(MBEDTLS_ECP_MAX_BITS)'
{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
type
  mbedtls_ecdsa_context* = mbedtls_ecp_keypair
  mbedtls_ecdsa_restart_ctx* = object
proc mbedtls_ecdsa_can_do*(gid: mbedtls_ecp_group_id): cint {.importc, cdecl.}
proc mbedtls_ecdsa_sign*(grp: ptr mbedtls_ecp_group; r: ptr mbedtls_mpi;
                         s: ptr mbedtls_mpi; d: ptr mbedtls_mpi;
                         buf: ptr byte; blen: uint; f_rng: proc (a1: pointer;
    a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.importc,
    cdecl.}
proc mbedtls_ecdsa_sign_det_ext*(grp: ptr mbedtls_ecp_group; r: ptr mbedtls_mpi;
                                 s: ptr mbedtls_mpi; d: ptr mbedtls_mpi;
                                 buf: ptr byte; blen: uint;
                                 md_alg: mbedtls_md_type_t; f_rng_blind: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng_blind: pointer): cint {.
    importc, cdecl.}
proc mbedtls_ecdsa_sign_restartable*(grp: ptr mbedtls_ecp_group;
                                     r: ptr mbedtls_mpi; s: ptr mbedtls_mpi;
                                     d: ptr mbedtls_mpi; buf: ptr byte;
                                     blen: uint; f_rng: proc (a1: pointer;
    a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer; f_rng_blind: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.};
                                     p_rng_blind: pointer;
                                     rs_ctx: ptr mbedtls_ecdsa_restart_ctx): cint {.
    importc, cdecl.}
proc mbedtls_ecdsa_sign_det_restartable*(grp: ptr mbedtls_ecp_group;
    r: ptr mbedtls_mpi; s: ptr mbedtls_mpi; d: ptr mbedtls_mpi; buf: ptr byte;
    blen: uint; md_alg: mbedtls_md_type_t;
    f_rng_blind: proc (a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.};
    p_rng_blind: pointer; rs_ctx: ptr mbedtls_ecdsa_restart_ctx): cint {.
    importc, cdecl.}
proc mbedtls_ecdsa_verify*(grp: ptr mbedtls_ecp_group; buf: ptr byte;
                           blen: uint; Q: ptr mbedtls_ecp_point;
                           r: ptr mbedtls_mpi; s: ptr mbedtls_mpi): cint {.
    importc, cdecl.}
proc mbedtls_ecdsa_verify_restartable*(grp: ptr mbedtls_ecp_group;
                                       buf: ptr byte; blen: uint;
                                       Q: ptr mbedtls_ecp_point;
                                       r: ptr mbedtls_mpi; s: ptr mbedtls_mpi;
                                       rs_ctx: ptr mbedtls_ecdsa_restart_ctx): cint {.
    importc, cdecl.}
proc mbedtls_ecdsa_write_signature*(ctx: ptr mbedtls_ecdsa_context;
                                    md_alg: mbedtls_md_type_t; hash: ptr byte;
                                    hlen: uint; sig: ptr byte; sig_size: uint;
                                    slen: ptr uint; f_rng: proc (a1: pointer;
    a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.importc,
    cdecl.}
proc mbedtls_ecdsa_write_signature_restartable*(ctx: ptr mbedtls_ecdsa_context;
    md_alg: mbedtls_md_type_t; hash: ptr byte; hlen: uint; sig: ptr byte;
    sig_size: uint; slen: ptr uint;
    f_rng: proc (a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.};
    p_rng: pointer; rs_ctx: ptr mbedtls_ecdsa_restart_ctx): cint {.importc,
    cdecl.}
proc mbedtls_ecdsa_read_signature*(ctx: ptr mbedtls_ecdsa_context;
                                   hash: ptr byte; hlen: uint;
                                   sig: ptr byte; slen: uint): cint {.importc,
    cdecl.}
proc mbedtls_ecdsa_read_signature_restartable*(ctx: ptr mbedtls_ecdsa_context;
    hash: ptr byte; hlen: uint; sig: ptr byte; slen: uint;
    rs_ctx: ptr mbedtls_ecdsa_restart_ctx): cint {.importc, cdecl.}
proc mbedtls_ecdsa_genkey*(ctx: ptr mbedtls_ecdsa_context;
                           gid: mbedtls_ecp_group_id; f_rng: proc (a1: pointer;
    a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.importc,
    cdecl.}
proc mbedtls_ecdsa_from_keypair*(ctx: ptr mbedtls_ecdsa_context;
                                 key: ptr mbedtls_ecp_keypair): cint {.importc,
    cdecl.}
proc mbedtls_ecdsa_init*(ctx: ptr mbedtls_ecdsa_context) {.importc, cdecl.}
proc mbedtls_ecdsa_free*(ctx: ptr mbedtls_ecdsa_context) {.importc, cdecl.}
{.pop.}
