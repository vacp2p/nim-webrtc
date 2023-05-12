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
import "ssl"
import "platform_util"
import "platform_time"
import "bignum"
import "ecp"
import "ssl_ciphersuites"
import "pk"
import "md"
import "rsa"
import "ecdsa"
import "cipher"
import "x509_crt"
import "x509"
import "asn1"
import "x509_crl"
import "dhm"
import "ecdh"
import "md5"
import "ripemd160"
import "sha1"
import "sha256"
import "sha512"
import "cmac"
import "gcm"
import "ccm"
import "chachapoly"
import "poly1305"
import "chacha20"
import "ecjpake"
{.compile: "./mbedtls/library/ssl_cache.c".}
# Generated @ 2023-05-11T11:19:14+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/ssl_cache.h

{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
const
  MBEDTLS_SSL_CACHE_DEFAULT_TIMEOUT* = 86400
  MBEDTLS_SSL_CACHE_DEFAULT_MAX_ENTRIES* = 50
type
  mbedtls_ssl_cache_context* {.bycopy.} = object
    private_chain*: ptr mbedtls_ssl_cache_entry
    private_timeout*: cint
    private_max_entries*: cint

  mbedtls_ssl_cache_entry* {.bycopy.} = object
    private_timestamp*: mbedtls_time_t
    private_session_id*: array[32, byte]
    private_session_id_len*: uint
    private_session*: ptr byte
    private_session_len*: uint
    private_next*: ptr mbedtls_ssl_cache_entry

proc mbedtls_ssl_cache_init*(cache: ptr mbedtls_ssl_cache_context) {.importc,
    cdecl.}
proc mbedtls_ssl_cache_get*(data: pointer; session_id: ptr byte;
                            session_id_len: uint;
                            session: ptr mbedtls_ssl_session): cint {.importc,
    cdecl.}
proc mbedtls_ssl_cache_set*(data: pointer; session_id: ptr byte;
                            session_id_len: uint;
                            session: ptr mbedtls_ssl_session): cint {.importc,
    cdecl.}
proc mbedtls_ssl_cache_remove*(data: pointer; session_id: ptr byte;
                               session_id_len: uint): cint {.importc, cdecl.}
proc mbedtls_ssl_cache_set_timeout*(cache: ptr mbedtls_ssl_cache_context;
                                    timeout: cint) {.importc, cdecl.}
proc mbedtls_ssl_cache_set_max_entries*(cache: ptr mbedtls_ssl_cache_context;
                                        max: cint) {.importc, cdecl.}
proc mbedtls_ssl_cache_free*(cache: ptr mbedtls_ssl_cache_context) {.importc,
    cdecl.}
{.pop.}
