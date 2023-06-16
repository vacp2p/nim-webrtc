# Nim-WebRTC
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import std/times
import chronos
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

type
  DtlsConn* = ref object of WebRTCConn
    recvData: seq[seq[byte]]
    recvEvent: AsyncEvent
    handlesFut: Future[void]

    entropy: mbedtls_entropy_context
    ctr_drbg: mbedtls_ctr_drbg_context

proc mbedtls_pk_rsa(pk: mbedtls_pk_context): ptr mbedtls_rsa_context =
  var key = pk
  case mbedtls_pk_get_type(addr key):
    of MBEDTLS_PK_RSA:
      return cast[ptr mbedtls_rsa_context](pk.private_pk_ctx)
    else:
      return nil

proc generateKey(self: DtlsConn): mbedtls_pk_context =
  var res: mbedtls_pk_context
  mbedtls_pk_init(addr res)
  echo "=> ", mbedtls_pk_setup(addr res, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))
  echo "=> ", mbedtls_rsa_gen_key(mbedtls_pk_rsa(res),
                             mbedtls_ctr_drbg_random,
                             cast[pointer](addr self.ctr_drbg), 4096, 65537)
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
  mbedtls_x509write_crt_init(addr write_cert)
  mbedtls_x509write_crt_set_md_alg(addr write_cert, MBEDTLS_MD_SHA256);
  mbedtls_x509write_crt_set_subject_key(addr write_cert, addr issuer_key)
  mbedtls_x509write_crt_set_issuer_key(addr write_cert, addr issuer_key)
  echo mbedtls_x509write_crt_set_subject_name(addr write_cert, name.cstring)
  echo mbedtls_x509write_crt_set_issuer_name(addr write_cert, name.cstring)
  echo mbedtls_x509write_crt_set_validity(addr write_cert, time_from.cstring, time_to.cstring)
  echo mbedtls_x509write_crt_set_basic_constraints(addr write_cert, 0, -1)
  echo mbedtls_x509write_crt_set_subject_key_identifier(addr write_cert)
  echo mbedtls_x509write_crt_set_authority_key_identifier(addr write_cert);
  mbedtls_mpi_init(addr serial_mpi);
  var
    serial_hex = newString(16)
    buf = newString(4096)
  echo mbedtls_mpi_read_string(addr serial_mpi, 16, serial_hex.cstring);
  echo mbedtls_x509write_crt_set_serial(addr write_cert, addr serial_mpi)
  echo mbedtls_x509write_crt_pem(addr write_cert, cast[ptr byte](buf.cstring), buf.len().uint,
                            mbedtls_ctr_drbg_random, addr self.ctr_drbg)
  echo mbedtls_x509_crt_parse(addr result, cast[ptr byte](buf.cstring), buf.cstring.len().uint + 1)

method init*(self: DtlsConn, conn: WebRTCConn, address: TransportAddress) {.async.} =
  await procCall(WebRTCConn(self).init(conn, address))

  mbedtls_ctr_drbg_init(cast[ptr mbedtls_ctr_drbg_context](addr self.ctr_drbg))
  mbedtls_entropy_init(cast[ptr mbedtls_entropy_context](addr self.entropy))
  if mbedtls_ctr_drbg_seed(cast[ptr mbedtls_ctr_drbg_context](addr self.ctr_drbg),
                           mbedtls_entropy_func, cast[pointer](addr self.entropy),
                           nil, 0) != 0:
    echo "Something's not quite right"
    return

proc testtruc() =
  var write_cert: mbedtls_x509write_cert
  mbedtls_x509write_crt_init(cast[ptr mbedtls_x509write_cert](addr write_cert))
  echo mbedtls_x509write_crt_set_subject_name(
    cast[ptr mbedtls_x509write_cert](addr write_cert), "aa".cstring)


method close*(self: WebRTCConn) {.async.} =
  discard

method write*(self: WebRTCConn, msg: seq[byte]) {.async.} =
  discard

method read*(self: WebRTCConn): Future[seq[byte]] {.async.} =
  discard

proc main {.async.} =
  let laddr = initTAddress("127.0.0.1:" & "4242")
  var dtls = DtlsConn()
  await dtls.init(nil, laddr)
  let cert = dtls.generateCertificate()

waitFor(main())
