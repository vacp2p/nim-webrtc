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
import ./utils, ../webrtc_connection

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
