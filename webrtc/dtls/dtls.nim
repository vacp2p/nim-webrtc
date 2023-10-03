# Nim-WebRTC
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import times, sequtils
import strutils # to remove
import chronos, chronicles
import ./utils, ../webrtc_connection

import mbedtls/ssl
import mbedtls/ssl_cookie
import mbedtls/ssl_cache
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
    sendFuture: Future[void]

    timer: mbedtls_timing_delay_context

    ssl: mbedtls_ssl_context
    config: mbedtls_ssl_config
    cookie: mbedtls_ssl_cookie_ctx
    cache: mbedtls_ssl_cache_context

    ctr_drbg: mbedtls_ctr_drbg_context
    entropy: mbedtls_entropy_context

proc dtlsSend*(ctx: pointer, buf: ptr byte, len: uint): cint {.cdecl.} =
  var self = cast[DtlsConn](ctx)
  var toWrite = newSeq[byte](len)
  if len > 0:
    copyMem(addr toWrite[0], buf, len)
  self.sendFuture = self.conn.write(toWrite)
  result = len.cint

proc dtlsRecv*(ctx: pointer, buf: ptr byte, len: uint): cint {.cdecl.} =
  var self = cast[DtlsConn](ctx)
  result = self.recvData[0].len().cint
  copyMem(buf, addr self.recvData[0][0], self.recvData[0].len())
  self.recvData.delete(0..0)

method init*(self: DtlsConn, conn: WebRTCConn, address: TransportAddress) {.async.} =
  await procCall(WebRTCConn(self).init(conn, address))

method write*(self: DtlsConn, msg: seq[byte]) {.async.} =
  var buf = msg
  discard mbedtls_ssl_write(addr self.ssl, cast[ptr byte](addr buf[0]), buf.len().uint)

method read*(self: DtlsConn): Future[seq[byte]] {.async.} =
  return await self.conn.read()

method close*(self: DtlsConn) {.async.} =
  discard

method getRemoteAddress*(self: DtlsConn): TransportAddress =
  self.conn.getRemoteAddress()

type
  Dtls* = ref object of RootObj
    address: TransportAddress
    started: bool

proc start*(self: Dtls, address: TransportAddress) =
  if self.started:
    warn "Already started"
    return

  self.address = address
  self.started = true

proc stop*(self: Dtls) =
  if not self.started:
    warn "Already stopped"
    return

  self.started = false

proc handshake(self: DtlsConn) {.async.} =
  var endpoint =
    if self.ssl.private_conf.private_endpoint == MBEDTLS_SSL_IS_SERVER:
      MBEDTLS_ERR_SSL_WANT_READ
    else:
      MBEDTLS_ERR_SSL_WANT_WRITE

  while self.ssl.private_state != MBEDTLS_SSL_HANDSHAKE_OVER:
    if endpoint == MBEDTLS_ERR_SSL_WANT_READ or
        self.ssl.private_state == MBEDTLS_SSL_CLIENT_KEY_EXCHANGE:
      self.recvData.add(await self.conn.read())
      var ta = self.getRemoteAddress()
      case ta.family
      of AddressFamily.IPv4:
        mb_ssl_set_client_transport_id(self.ssl, ta.address_v4)
      of AddressFamily.IPv6:
        mb_ssl_set_client_transport_id(self.ssl, ta.address_v6)
      else:
        discard # TODO: raise ?

    self.sendFuture = nil
    let res = mb_ssl_handshake_step(self.ssl)
    if not self.sendFuture.isNil(): await self.sendFuture
    if res == MBEDTLS_ERR_SSL_WANT_READ or res == MBEDTLS_ERR_SSL_WANT_WRITE:
      continue
    elif res == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED:
      mb_ssl_session_reset(self.ssl)
      endpoint = MBEDTLS_ERR_SSL_WANT_READ
      continue
    elif res != 0:
      break # raise whatever
    endpoint = res

proc accept*(self: Dtls, conn: WebRTCConn): Future[DtlsConn] {.async.} =
  var
    selfvar = self
    res = DtlsConn()
  let v = cast[pointer](res)

  await res.init(conn, self.address)
  mb_ssl_init(res.ssl)
  mb_ssl_config_init(res.config)
  mb_ssl_cookie_init(res.cookie)
  mb_ssl_cache_init(res.cache)

  mb_ctr_drbg_init(res.ctr_drbg)
  mb_entropy_init(res.entropy)
  mb_ctr_drbg_seed(res.ctr_drbg, mbedtls_entropy_func, res.entropy, nil, 0)

  var pkey = res.ctr_drbg.generateKey()
  var srvcert = res.ctr_drbg.generateCertificate(pkey)

  mb_ssl_config_defaults(res.config,
                         MBEDTLS_SSL_IS_SERVER,
                         MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                         MBEDTLS_SSL_PRESET_DEFAULT)
  mb_ssl_conf_rng(res.config, mbedtls_ctr_drbg_random, res.ctr_drbg)
  mb_ssl_conf_read_timeout(res.config, 10000) # in milliseconds
  mb_ssl_conf_ca_chain(res.config, srvcert.next, nil)
  mb_ssl_conf_own_cert(res.config, srvcert, pkey)
  mb_ssl_cookie_setup(res.cookie, mbedtls_ctr_drbg_random, res.ctr_drbg)
  mb_ssl_conf_dtls_cookies(res.config, res.cookie)
  mb_ssl_set_timer_cb(res.ssl, res.timer)
  # Add the cookie management (it works without, but it's more secure)
  mb_ssl_setup(res.ssl, res.config)
  mb_ssl_session_reset(res.ssl)
  mb_ssl_set_bio(res.ssl, cast[pointer](res),
                 dtlsSend, dtlsRecv, nil)
  await res.handshake()
  return res

proc dial*(self: Dtls, address: TransportAddress): DtlsConn =
  discard

import ../udp_connection
proc main() {.async.} =
  let laddr = initTAddress("127.0.0.1:4433")
  let udp = UdpConn()
  await udp.init(nil, laddr)
  let dtls = Dtls()
  dtls.start(laddr)
  let x = await dtls.accept(udp)
  echo "After accept"

waitFor(main())
