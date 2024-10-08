# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import chronos, chronicles
import
  mbedtls/[
    ssl, ssl_cookie, ssl_cache, pk, md, ctr_drbg, rsa, x509, x509_crt, bignum, error,
    net_sockets, timing,
  ]
import ../errors, ../stun/[stun_connection], ./dtls_utils

logScope:
  topics = "webrtc dtls_conn"

const DtlsConnTracker* = "webrtc.dtls.conn"

type
  DtlsConnOnClose* = proc() {.raises: [], gcsafe.}

  MbedTLSCtx = object
    ssl: mbedtls_ssl_context
    config: mbedtls_ssl_config
    cookie: mbedtls_ssl_cookie_ctx
    cache: mbedtls_ssl_cache_context
    timer: mbedtls_timing_delay_context
    pkey: mbedtls_pk_context
    srvcert: mbedtls_x509_crt
    ctr_drbg: mbedtls_ctr_drbg_context

  DtlsConn* = ref object
    # DtlsConn is a Dtls connection receiving and sending data using
    # the underlying Stun Connection
    conn: StunConn # The wrapper protocol Stun Connection
    raddr: TransportAddress # Remote address
    dataRecv: seq[byte] # data received which will be read by SCTP
    dataToSend: seq[byte]
    # This sequence is set by synchronous Mbed-TLS `dtlsSend` callbacks
    # and sent, if set, once the synchronous functions ends

    # Close connection management
    closed: bool
    onClose: seq[DtlsConnOnClose]

    # Local and Remote certificate, needed by wrapped protocol DataChannel
    # and by libp2p
    localCert: seq[byte]
    remoteCert: seq[byte]

    # Mbed-TLS contexts
    ctx: MbedTLSCtx

proc isClosed*(self: DtlsConn): bool =
  return self.closed

proc getRemoteCertificateCallback(
    ctx: pointer, pcert: ptr mbedtls_x509_crt, state: cint, pflags: ptr uint32
): cint {.cdecl.} =
  # getRemoteCertificateCallback is the procedure called by mbedtls when
  # receiving the remote certificate. It's usually used to verify the validity
  # of the certificate, we don't do it. We use this procedure to store the remot
  # certificate as it's mandatory to have it for the Prologue of the Noise
  # protocol, aswell as the localCertificate.
  var self = cast[DtlsConn](ctx)
  let cert = pcert[]

  self.remoteCert = newSeq[byte](cert.raw.len)
  copyMem(addr self.remoteCert[0], cert.raw.p, cert.raw.len)
  return 0

proc dtlsSend(ctx: pointer, buf: ptr byte, len: uint): cint {.cdecl.} =
  # dtlsSend is the procedure called by mbedtls when data needs to be sent.
  # As the StunConn's write proc is asynchronous and dtlsSend cannot be async,
  # we store the message to be sent and it after the end of the function
  # (see write or dtlsHanshake for example).
  var self = cast[DtlsConn](ctx)
  self.dataToSend = newSeq[byte](len)
  if len > 0:
    copyMem(addr self.dataToSend[0], buf, len)
  trace "dtls send", len
  result = len.cint

proc dtlsRecv(ctx: pointer, buf: ptr byte, len: uint): cint {.cdecl.} =
  # dtlsRecv is the procedure called by mbedtls when data needs to be received.
  # As we cannot asynchronously await for data to be received, we use a data received
  # queue. If this queue is empty, we return `MBEDTLS_ERR_SSL_WANT_READ` for us to await
  # when the mbedtls proc resumed (see read or dtlsHandshake for example)
  let self = cast[DtlsConn](ctx)
  if self.dataRecv.len() == 0:
    return MBEDTLS_ERR_SSL_WANT_READ

  copyMem(buf, addr self.dataRecv[0], self.dataRecv.len())
  result = self.dataRecv.len().cint
  self.dataRecv = @[]
  trace "dtls receive", len, result

proc new*(T: type DtlsConn, conn: StunConn): T =
  ## Initialize a Dtls Connection
  ##
  var self = T(conn: conn)
  self.raddr = conn.raddr
  self.closed = false
  return self

proc dtlsConnInit(self: DtlsConn) =
  mb_ssl_init(self.ctx.ssl)
  mb_ssl_config_init(self.ctx.config)
  mb_ssl_conf_rng(self.ctx.config, mbedtls_ctr_drbg_random, self.ctx.ctr_drbg)
  mb_ssl_conf_read_timeout(self.ctx.config, 10000) # in milliseconds
  mb_ssl_conf_ca_chain(self.ctx.config, self.ctx.srvcert.next, nil)
  mb_ssl_set_timer_cb(self.ctx.ssl, self.ctx.timer)
  mb_ssl_set_verify(self.ctx.ssl, getRemoteCertificateCallback, self)
  mb_ssl_set_bio(self.ctx.ssl, cast[pointer](self), dtlsSend, dtlsRecv, nil)

proc acceptInit*(
    self: DtlsConn,
    ctr_drbg: mbedtls_ctr_drbg_context,
    pkey: mbedtls_pk_context,
    srvcert: mbedtls_x509_crt,
    localCert: seq[byte],
) =
  try:
    self.ctx.ctr_drbg = ctr_drbg
    self.ctx.pkey = pkey
    self.ctx.srvcert = srvcert
    self.localCert = localCert

    self.dtlsConnInit()
    mb_ssl_cookie_init(self.ctx.cookie)
    mb_ssl_cache_init(self.ctx.cache)
    mb_ssl_config_defaults(
      self.ctx.config, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_DATAGRAM,
      MBEDTLS_SSL_PRESET_DEFAULT,
    )
    mb_ssl_conf_own_cert(self.ctx.config, self.ctx.srvcert, self.ctx.pkey)
    mb_ssl_cookie_setup(self.ctx.cookie, mbedtls_ctr_drbg_random, self.ctx.ctr_drbg)
    mb_ssl_conf_dtls_cookies(self.ctx.config, addr self.ctx.cookie)
    mb_ssl_setup(self.ctx.ssl, self.ctx.config)
    mb_ssl_session_reset(self.ctx.ssl)
    mb_ssl_conf_authmode(self.ctx.config, MBEDTLS_SSL_VERIFY_OPTIONAL)
  except MbedTLSError as exc:
    raise newException(WebRtcError, "DTLS - Accept initialization: " & exc.msg, exc)

proc connectInit*(self: DtlsConn, ctr_drbg: mbedtls_ctr_drbg_context) =
  try:
    self.ctx.ctr_drbg = ctr_drbg
    self.ctx.pkey = self.ctx.ctr_drbg.generateKey()
    self.ctx.srvcert = self.ctx.ctr_drbg.generateCertificate(self.ctx.pkey)
    self.localCert = newSeq[byte](self.ctx.srvcert.raw.len)
    copyMem(addr self.localCert[0], self.ctx.srvcert.raw.p, self.ctx.srvcert.raw.len)

    self.dtlsConnInit()
    mb_ssl_config_defaults(
      self.ctx.config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_DATAGRAM,
      MBEDTLS_SSL_PRESET_DEFAULT,
    )
    mb_ssl_setup(self.ctx.ssl, self.ctx.config)
    mb_ssl_conf_authmode(self.ctx.config, MBEDTLS_SSL_VERIFY_OPTIONAL)
  except MbedTLSError as exc:
    raise newException(WebRtcError, "DTLS - Connect initialization: " & exc.msg, exc)

proc addOnClose*(self: DtlsConn, onCloseProc: DtlsConnOnClose) =
  ## Adds a proc to be called when DtlsConn is closed
  ##
  self.onClose.add(onCloseProc)

proc dtlsHandshake*(
    self: DtlsConn, isServer: bool
) {.async: (raises: [CancelledError, WebRtcError]).} =
  var shouldRead = isServer
  try:
    while self.ctx.ssl.private_state != MBEDTLS_SSL_HANDSHAKE_OVER:
      if shouldRead:
        if isServer:
          case self.raddr.family
          of AddressFamily.IPv4:
            mb_ssl_set_client_transport_id(self.ctx.ssl, self.raddr.address_v4)
          of AddressFamily.IPv6:
            mb_ssl_set_client_transport_id(self.ctx.ssl, self.raddr.address_v6)
          else:
            raiseAssert("Remote address must be IPv4 or IPv6")
        let (data, _) = await self.conn.read()
        self.dataRecv = data
      self.dataToSend = @[]
      let res = mb_ssl_handshake_step(self.ctx.ssl)
      if self.dataToSend.len() > 0:
        await self.conn.write(self.dataToSend)
      self.dataToSend = @[]
      shouldRead = false
      if res == MBEDTLS_ERR_SSL_WANT_WRITE:
        continue
      elif res == MBEDTLS_ERR_SSL_WANT_READ:
        shouldRead = true
        continue
      elif res == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED:
        mb_ssl_session_reset(self.ctx.ssl)
        shouldRead = isServer
        continue
      elif res != 0:
        raise newException(WebRtcError, "DTLS - " & $(res.mbedtls_high_level_strerr()))
  except MbedTLSError as exc:
    trace "Dtls handshake error", errorMsg = exc.msg
    raise newException(WebRtcError, "DTLS - Handshake error", exc)
  trackCounter(DtlsConnTracker)

proc close*(self: DtlsConn) {.async: (raises: [CancelledError, WebRtcError]).} =
  ## Close a Dtls Connection
  ##
  if self.closed:
    debug "Try to close an already closed DtlsConn"
    return
  self.closed = true
  self.dataToSend = @[]
  let x = mbedtls_ssl_close_notify(addr self.ctx.ssl)
  if self.dataToSend.len() > 0:
    await self.conn.write(self.dataToSend)
  self.dataToSend = @[]
  untrackCounter(DtlsConnTracker)
  await self.conn.close()
  for onCloseProc in self.onClose:
    onCloseProc()
  self.onClose = @[]

proc write*(
    self: DtlsConn, msg: seq[byte]
) {.async: (raises: [CancelledError, WebRtcError]).} =
  ## Write a message using mbedtls_ssl_write
  ##
  # Mbed-TLS will wrap the message properly and call `dtlsSend` callback.
  # `dtlsSend` will store the message to be sent on the higher Stun connection.
  if self.closed:
    debug "Try to write on an already closed DtlsConn"
    return
  var buf = msg
  try:
    self.dataToSend = @[]
    let write = mb_ssl_write(self.ctx.ssl, buf)
    if self.dataToSend.len() > 0:
      await self.conn.write(self.dataToSend)
    self.dataToSend = @[]
    trace "Dtls write", msgLen = msg.len(), actuallyWrote = write
  except MbedTLSError as exc:
    trace "Dtls write error", errorMsg = exc.msg
    raise newException(WebRtcError, "DTLS - " & exc.msg, exc)

proc read*(
    self: DtlsConn
): Future[seq[byte]] {.async: (raises: [CancelledError, WebRtcError]).} =
  ## Read the next received message by StunConn.
  ## Uncypher it using mbedtls_ssl_read.
  ##
  # First we read the StunConn using the asynchronous `StunConn.read` procedure.
  # When we received data, we stored it in `DtlsConn.dataRecv` and call `dtlsRecv`
  # callback using mbedtls in order to decypher it.
  if self.closed:
    debug "Try to read on an already closed DtlsConn"
    return
  var res = newSeq[byte](8192)
  while true:
    let (data, _) = await self.conn.read()
    self.dataRecv = data
    let length =
      mbedtls_ssl_read(addr self.ctx.ssl, cast[ptr byte](addr res[0]), res.len().uint)
    if length == MBEDTLS_ERR_SSL_WANT_READ:
      continue
    if length < 0:
      raise newException(
        WebRtcError, "DTLS - " & $(length.cint.mbedtls_high_level_strerr())
      )
    res.setLen(length)
    return res

proc remoteCertificate*(conn: DtlsConn): seq[byte] =
  ## Get the remote certificate
  ##
  conn.remoteCert

proc localCertificate*(conn: DtlsConn): seq[byte] =
  ## Get the local certificate
  ##
  conn.localCert

proc remoteAddress*(conn: DtlsConn): TransportAddress =
  ## Get the remote address
  ##
  conn.raddr
