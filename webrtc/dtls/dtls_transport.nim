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

type
  Dtls* = ref object of RootObj
    connections: Table[TransportAddress, DtlsConn]
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
    connections: initTable[TransportAddress, DtlsConn](),
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
  return self

proc stop*(self: Dtls) {.async.} =
  if not self.started:
    warn "Already stopped"
    return

  await allFutures(toSeq(self.connections.values()).mapIt(it.close()))
  self.started = false

proc localCertificate*(self: Dtls): seq[byte] =
  ## Local certificate getter
  self.localCert

proc cleanupDtlsConn(self: Dtls, conn: DtlsConn) {.async.} =
  # Waiting for a connection to be closed to remove it from the table
  await conn.join()
  self.connections.del(conn.raddr)

proc accept*(self: Dtls): Future[DtlsConn] {.async.} =
  ## Accept a Dtls Connection
  ##
  var res = DtlsConn.new(await self.transport.accept(), self.laddr)
  res.acceptInit(self.ctr_drbg, self.serverPrivKey, self.serverCert, self.localCert)

  while true:
    try:
      self.connections[res.raddr] = res
      await res.dtlsHandshake(true)
      asyncSpawn self.cleanupDtlsConn(res)
      break
    except WebRtcError as exc:
      trace "Handshake fails, try accept another connection",
            remoteAddress = res.raddr, error = exc.msg
      self.connections.del(res.raddr)
      res.conn = await self.transport.accept()
  return res

proc connect*(self: Dtls, raddr: TransportAddress): Future[DtlsConn] {.async.} =
  ## Connect to a remote address, creating a Dtls Connection
  var res = DtlsConn.new(await self.transport.connect(raddr), self.laddr)
  res.connectInit(self.ctr_drbg)

  try:
    self.connections[raddr] = res
    await res.dtlsHandshake(false)
    asyncSpawn self.cleanupDtlsConn(res)
  except WebRtcError as exc:
    trace "Handshake fails", remoteAddress = raddr, error = exc.msg
    self.connections.del(raddr)
    raise exc

  return res
