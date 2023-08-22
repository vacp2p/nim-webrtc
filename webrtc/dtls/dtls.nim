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

    timer: mbedtls_timing_delay_context

    config: mbedtls_ssl_config
    ssl: mbedtls_ssl_context

proc dtlsSend*(ctx: pointer, buf: ptr byte, len: uint): cint {.cdecl.} =
  echo "Send: ", len
  let self = cast[DtlsConn](ctx)
  self.sendEvent.fire()

proc dtlsRecv*(ctx: pointer, buf: ptr byte, len: uint): cint {.cdecl.} =
  var self = cast[DtlsConn](ctx)[]
  echo "Recv: ", self.recvData[0].len(), " ", len
  echo ctx.repr
  result = self.recvData[0].len().cint
  copyMem(buf, addr self.recvData[0][0], self.recvData[0].len())
  self.recvData.delete(0..0)

method init*(self: DtlsConn, conn: WebRTCConn, address: TransportAddress) {.async.} =
  await procCall(WebRTCConn(self).init(conn, address))
#  self.recvEvent = AsyncEvent()
#  self.sendEvent = AsyncEvent()
#

method write*(self: DtlsConn, msg: seq[byte]) {.async.} =
  var buf = msg
  self.sendEvent.clear()
  discard mbedtls_ssl_write(addr self.ssl, cast[ptr byte](addr buf[0]), buf.len().uint)
  await self.sendEvent.wait()

method read*(self: DtlsConn): Future[seq[byte]] {.async.} =
  return await self.conn.read()

method close*(self: DtlsConn) {.async.} =
  discard

type
  Dtls* = ref object of RootObj
    ctr_drbg: mbedtls_ctr_drbg_context
    entropy: mbedtls_entropy_context

    address: TransportAddress
    started: bool

proc start*(self: Dtls, address: TransportAddress) =
  if self.started:
    warn "Already started"
    return

  self.address = address
  self.started = true
  mb_ctr_drbg_init(self.ctr_drbg)
  mb_entropy_init(self.entropy)
  mb_ctr_drbg_seed(self.ctr_drbg, mbedtls_entropy_func,
                   self.entropy, nil, 0)

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
    echo "State: ", toHex(self.ssl.private_state.int)
    if endpoint == MBEDTLS_ERR_SSL_WANT_READ:
      self.recvData.add(await self.conn.read())
      echo "=====> ", self.recvData.len()
    let res = mbedtls_ssl_handshake_step(addr self.ssl)
    echo "Result handshake step: ", (-res).toHex, " ",
         (-MBEDTLS_ERR_SSL_WANT_READ).toHex, " ",
         (-MBEDTLS_ERR_SSL_WANT_WRITE).toHex
    if res == MBEDTLS_ERR_SSL_WANT_READ or res == MBEDTLS_ERR_SSL_WANT_WRITE:
      echo if res == MBEDTLS_ERR_SSL_WANT_READ: "WANT_READ" else: "WANT_WRITE"
      continue
    elif res != 0:
      break # raise whatever
    endpoint = res

proc accept*(self: Dtls, conn: WebRTCConn): Future[DtlsConn] {.async.} =
  echo "1"
  var
    srvcert = self.ctr_drbg.generateCertificate()
    pkey = self.ctr_drbg.generateKey()
    selfvar = self
    res = DtlsConn()
  let v = cast[pointer](res)
  echo v.repr

  await res.init(conn, self.address)
  mb_ssl_init(res.ssl)
  mb_ssl_config_init(res.config)
  mb_ssl_config_defaults(res.config,
                         MBEDTLS_SSL_IS_SERVER,
                         MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                         MBEDTLS_SSL_PRESET_DEFAULT)
  mb_ssl_conf_rng(res.config, mbedtls_ctr_drbg_random, self.ctr_drbg)
  mb_ssl_conf_read_timeout(res.config, 10000) # in milliseconds
  mb_ssl_conf_ca_chain(res.config, srvcert.next, nil)
  mb_ssl_conf_own_cert(res.config, srvcert, pkey)
  mbedtls_ssl_set_timer_cb(addr res.ssl, cast[pointer](addr res.timer),
                           mbedtls_timing_set_delay,
                           mbedtls_timing_get_delay)
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
  echo "Before accept"
  let x = await dtls.accept(udp)
  echo "After accept"

waitFor(main())
