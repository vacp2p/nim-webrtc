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
{.compile: "./mbedtls/library/ssl_cookie.c".}
# Generated @ 2023-05-11T11:19:14+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/ssl_cookie.h

{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
const
  MBEDTLS_SSL_COOKIE_TIMEOUT* = 60
type
  mbedtls_ssl_cookie_ctx* {.bycopy.} = object
    private_hmac_ctx*: mbedtls_md_context_t
    private_timeout*: culong

var
  mbedtls_ssl_cookie_write* {.importc.}: mbedtls_ssl_cookie_write_t
  mbedtls_ssl_cookie_check* {.importc.}: mbedtls_ssl_cookie_check_t
proc mbedtls_ssl_cookie_init*(ctx: ptr mbedtls_ssl_cookie_ctx) {.importc, cdecl.}
proc mbedtls_ssl_cookie_setup*(ctx: ptr mbedtls_ssl_cookie_ctx; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.
    importc, cdecl.}
proc mbedtls_ssl_cookie_set_timeout*(ctx: ptr mbedtls_ssl_cookie_ctx;
                                     delay: culong) {.importc, cdecl.}
proc mbedtls_ssl_cookie_free*(ctx: ptr mbedtls_ssl_cookie_ctx) {.importc, cdecl.}
{.pop.}
