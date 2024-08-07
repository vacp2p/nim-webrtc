# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import deques, tables, sequtils
import chronos, chronicles
import ./[dtls_utils, dtls_connection], ../errors,
       ../stun/[stun_connection, stun_transport]

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

# Implementation of a DTLS client and a DTLS Server by using the Mbed-TLS library.
# Multiple things here are unintuitive partly because of the callbacks
# used by Mbed-TLS which cannot be async.

const DtlsTransportTracker* = "webrtc.dtls.transport"

type
  DtlsConnAndCleanup = object
    connection: DtlsConn
    cleanup: Future[void].Raising([])
  Dtls* = ref object of RootObj
    connections: Table[TransportAddress, DtlsConnAndCleanup]
    transport: Stun
    laddr*: TransportAddress
    started: bool
    ctr_drbg: mbedtls_ctr_drbg_context
    entropy: mbedtls_entropy_context

    serverPrivKey: mbedtls_pk_context
    serverCert: mbedtls_x509_crt
    localCert: seq[byte]

proc new*(T: type Dtls, transport: Stun): T =
  var self = T(
    connections: initTable[TransportAddress, DtlsConnAndCleanup](),
    transport: transport,
    laddr: transport.laddr,
    started: true
  )

  mb_ctr_drbg_init(self.ctr_drbg)
  mb_entropy_init(self.entropy)
  mb_ctr_drbg_seed(self.ctr_drbg, mbedtls_entropy_func, self.entropy, nil, 0)

  self.serverPrivKey = self.ctr_drbg.generateKey()
  self.serverCert = self.ctr_drbg.generateCertificate(self.serverPrivKey)
  self.localCert = newSeq[byte](self.serverCert.raw.len)
  copyMem(addr self.localCert[0], self.serverCert.raw.p, self.serverCert.raw.len)
  trackCounter(DtlsTransportTracker)
  return self

proc stop*(self: Dtls) {.async: (raises: [CancelledError]).} =
  ## Stop the Dtls transport. Stop every opened connections.
  ##
  if not self.started:
    warn "Already stopped"
    return

  self.started = false
  await allFutures(toSeq(self.connections.values()).mapIt(it.connection.close()))
  await allFutures(toSeq(self.connections.values()).mapIt(it.cleanup))
  untrackCounter(DtlsTransportTracker)

proc localCertificate*(self: Dtls): seq[byte] =
  ## Local certificate getter
  self.localCert

proc cleanupDtlsConn(self: Dtls, conn: DtlsConn) {.async: (raises: []).} =
  # Waiting for a connection to be closed to remove it from the table
  try:
    await conn.join()
  except CancelledError as exc:
    discard

  self.connections.del(conn.raddr)

proc accept*(self: Dtls): Future[DtlsConn] {.async: (raises: [CancelledError, WebRtcError]).} =
  ## Accept a Dtls Connection
  ##
  if not self.started:
    raise newException(WebRtcError, "DTLS - Dtls transport not started")
  var res: DtlsConn

  while true:
    let stunConn = await self.transport.accept()
    if stunConn.raddr.family == AddressFamily.IPv4 or stunConn.raddr.family == AddressFamily.IPv6:
      try:
        res = DtlsConn.new(stunConn, self.laddr)
        res.acceptInit(self.ctr_drbg, self.serverPrivKey, self.serverCert, self.localCert)
        await res.dtlsHandshake(true)
        self.connections[res.raddr] = DtlsConnAndCleanup(
          connection: res,
          cleanup: self.cleanupDtlsConn(res)
        )
        break
      except WebRtcError as exc:
        trace "Handshake fails, try accept another connection",
              remoteAddress = res.raddr, error = exc.msg
    self.connections.del(res.raddr)
  return res

proc connect*(
    self: Dtls,
    raddr: TransportAddress
): Future[DtlsConn] {.async: (raises: [CancelledError, WebRtcError]).} =
  ## Connect to a remote address, creating a Dtls Connection
  ##
  if not self.started:
    raise newException(WebRtcError, "DTLS - Dtls transport not started")
  if raddr.family != AddressFamily.IPv4 and raddr.family != AddressFamily.IPv6:
    raise newException(WebRtcError, "DTLS - Can only connect to IP address")
  var res = DtlsConn.new(await self.transport.connect(raddr), self.laddr)
  res.connectInit(self.ctr_drbg)

  try:
    await res.dtlsHandshake(false)
    self.connections[res.raddr] = DtlsConnAndCleanup(
      connection: res,
      cleanup: self.cleanupDtlsConn(res)
    )
  except WebRtcError as exc:
    trace "Handshake fails", remoteAddress = raddr, error = exc.msg
    self.connections.del(raddr)
    raise exc

  return res
