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
{.compile: "./mbedtls/library/net_sockets.c".}
# Generated @ 2023-05-11T11:19:11+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/net_sockets.h

{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
const
  MBEDTLS_ERR_NET_SOCKET_FAILED* = -0x00000042
  MBEDTLS_ERR_NET_CONNECT_FAILED* = -0x00000044
  MBEDTLS_ERR_NET_BIND_FAILED* = -0x00000046
  MBEDTLS_ERR_NET_LISTEN_FAILED* = -0x00000048
  MBEDTLS_ERR_NET_ACCEPT_FAILED* = -0x0000004A
  MBEDTLS_ERR_NET_RECV_FAILED* = -0x0000004C
  MBEDTLS_ERR_NET_SEND_FAILED* = -0x0000004E
  MBEDTLS_ERR_NET_CONN_RESET* = -0x00000050
  MBEDTLS_ERR_NET_UNKNOWN_HOST* = -0x00000052
  MBEDTLS_ERR_NET_BUFFER_TOO_SMALL* = -0x00000043
  MBEDTLS_ERR_NET_INVALID_CONTEXT* = -0x00000045
  MBEDTLS_ERR_NET_POLL_FAILED* = -0x00000047
  MBEDTLS_ERR_NET_BAD_INPUT_DATA* = -0x00000049
  MBEDTLS_NET_LISTEN_BACKLOG* = 10
  MBEDTLS_NET_PROTO_TCP* = 0
  MBEDTLS_NET_PROTO_UDP* = 1
  MBEDTLS_NET_POLL_READ* = 1
  MBEDTLS_NET_POLL_WRITE* = 2
type
  mbedtls_net_context* {.bycopy.} = object
    fd*: cint

proc mbedtls_net_init*(ctx: ptr mbedtls_net_context) {.importc, cdecl.}
proc mbedtls_net_connect*(ctx: ptr mbedtls_net_context; host: cstring;
                          port: cstring; proto: cint): cint {.importc, cdecl.}
proc mbedtls_net_bind*(ctx: ptr mbedtls_net_context; bind_ip: cstring;
                       port: cstring; proto: cint): cint {.importc, cdecl.}
proc mbedtls_net_accept*(bind_ctx: ptr mbedtls_net_context;
                         client_ctx: ptr mbedtls_net_context;
                         client_ip: pointer; buf_size: uint; ip_len: ptr uint): cint {.
    importc, cdecl.}
proc mbedtls_net_poll*(ctx: ptr mbedtls_net_context; rw: uint32; timeout: uint32): cint {.
    importc, cdecl.}
proc mbedtls_net_set_block*(ctx: ptr mbedtls_net_context): cint {.importc, cdecl.}
proc mbedtls_net_set_nonblock*(ctx: ptr mbedtls_net_context): cint {.importc,
    cdecl.}
proc mbedtls_net_usleep*(usec: culong) {.importc, cdecl.}
proc mbedtls_net_recv*(ctx: pointer; buf: ptr byte; len: uint): cint {.
    importc, cdecl.}
proc mbedtls_net_send*(ctx: pointer; buf: ptr byte; len: uint): cint {.
    importc, cdecl.}
proc mbedtls_net_recv_timeout*(ctx: pointer; buf: ptr byte; len: uint;
                               timeout: uint32): cint {.importc, cdecl.}
proc mbedtls_net_close*(ctx: ptr mbedtls_net_context) {.importc, cdecl.}
proc mbedtls_net_free*(ctx: ptr mbedtls_net_context) {.importc, cdecl.}
{.pop.}
