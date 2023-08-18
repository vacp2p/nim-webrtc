# Nim-WebRTC
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import std/times
import chronos, chronicles
import webrtc_connection

import mbedtls/ssl
import mbedtls/pk
import mbedtls/md
import mbedtls/entropy
import mbedtls/ctr_drbg
import mbedtls/rsa
import mbedtls/x509
import mbedtls/x509_crt
import mbedtls/bignum
import mbedtls/error
import mbedtls/net_sockets
import mbedtls/timing

logScope:
  topics = "webrtc dtls"

type
  DtlsConn* = ref object of WebRTCConn
    recvData: seq[seq[byte]]
    recvEvent: AsyncEvent
    sendEvent: AsyncEvent

    entropy: mbedtls_entropy_context
    ctr_drbg: mbedtls_ctr_drbg_context
    timer: mbedtls_timing_delay_context

    config: mbedtls_ssl_config
    ssl: mbedtls_ssl_context

proc mbedtls_pk_rsa(pk: mbedtls_pk_context): ptr mbedtls_rsa_context =
  var key = pk
  case mbedtls_pk_get_type(addr key):
    of MBEDTLS_PK_RSA:
      return cast[ptr mbedtls_rsa_context](pk.private_pk_ctx)
    else:
      return nil

proc generateKey(self: DtlsConn): mbedtls_pk_context =
  var res: mbedtls_pk_context
  mb_pk_init(res)
  discard mbedtls_pk_setup(addr res, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))
  mb_rsa_gen_key(mb_pk_rsa(res), mbedtls_ctr_drbg_random, self.ctr_drbg, 4096, 65537)
  return res

proc generateCertificate(self: DtlsConn): mbedtls_x509_crt =
  let
    name = "C=FR,O=webrtc,CN=wbrtc"
    time_format = initTimeFormat("YYYYMMddHHmmss")
    time_from = times.now().format(time_format)
    time_to = (times.now() + times.years(1)).format(time_format)

  var issuer_key = self.generateKey()
  var write_cert: mbedtls_x509write_cert
  var serial_mpi: mbedtls_mpi
  mb_x509write_crt_init(write_cert)
  mb_x509write_crt_set_md_alg(write_cert, MBEDTLS_MD_SHA256);
  mb_x509write_crt_set_subject_key(write_cert, issuer_key)
  mb_x509write_crt_set_issuer_key(write_cert, issuer_key)
  mb_x509write_crt_set_subject_name(write_cert, name)
  mb_x509write_crt_set_issuer_name(write_cert, name)
  mb_x509write_crt_set_validity(write_cert, time_from, time_to)
  mb_x509write_crt_set_basic_constraints(write_cert, 0, -1)
  mb_x509write_crt_set_subject_key_identifier(write_cert)
  mb_x509write_crt_set_authority_key_identifier(write_cert)
  mb_mpi_init(serial_mpi)
  let serial_hex = mb_mpi_read_string(serial_mpi, 16)
  mb_x509write_crt_set_serial(write_cert, serial_mpi)
  let buf = mb_x509write_crt_pem(write_cert, 4096, mbedtls_ctr_drbg_random, self.ctr_drbg)
  mb_x509_crt_parse(result, buf)

proc dtlsSend*(ctx: pointer, buf: ptr byte, len: uint): cint {.cdecl.} =
  echo "Send: ", len
  let self = cast[ptr DtlsConn](ctx)
  self.sendEvent.fire()

proc dtlsRecv*(ctx: pointer, buf: ptr byte, len: uint): cint {.cdecl.} =
  echo "Recv: ", len
  let self = cast[ptr DtlsConn](ctx)[]

  let x = self.read()

method init*(self: DtlsConn, conn: WebRTCConn, address: TransportAddress) {.async.} =
  await procCall(WebRTCConn(self).init(conn, address))
  self.recvEvent = AsyncEvent()
  self.sendEvent = AsyncEvent()

  mb_ctr_drbg_init(self.ctr_drbg)
  mb_entropy_init(self.entropy)
  mb_ctr_drbg_seed(self.ctr_drbg, mbedtls_entropy_func,
                   self.entropy, nil, 0)
  var
    srvcert = self.generateCertificate()
    pkey = self.generateKey()
    selfvar = self

  mb_ssl_init(self.ssl)
  mb_ssl_config_init(self.config)
  mb_ssl_config_defaults(self.config, MBEDTLS_SSL_IS_SERVER,
                         MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                         MBEDTLS_SSL_PRESET_DEFAULT)
  mb_ssl_conf_rng(self.config, mbedtls_ctr_drbg_random, self.ctr_drbg)
  mb_ssl_conf_read_timeout(self.config, 10000) # in milliseconds
  mb_ssl_conf_ca_chain(self.config, srvcert.next, nil)
  mb_ssl_conf_own_cert(self.config, srvcert, pkey)
  mbedtls_ssl_set_timer_cb(addr self.ssl, cast[pointer](addr self.timer),
                           mbedtls_timing_set_delay,
                           mbedtls_timing_get_delay)
  # cookie ?
  mb_ssl_setup(self.ssl, self.config)
  mb_ssl_session_reset(self.ssl)
  mb_ssl_set_bio(self.ssl, cast[pointer](addr selfvar),
                 dtlsSend, dtlsRecv, nil)
  while true:
    mb_ssl_handshake(self.ssl)

method write*(self: DtlsConn, msg: seq[byte]) {.async.} =
  var buf = msg
  self.sendEvent.clear()
  discard mbedtls_ssl_write(addr self.ssl, cast[ptr byte](addr buf[0]), buf.len().uint)
  await self.sendEvent.wait()

method read*(self: DtlsConn): Future[seq[byte]] {.async.} =
  return await self.conn.read()

method close*(self: DtlsConn) {.async.} =
  discard

proc main {.async.} =
  let laddr = initTAddress("127.0.0.1:" & "4242")
  var dtls = DtlsConn()
  await dtls.init(nil, laddr)

waitFor(main())
