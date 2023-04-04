# Nim-WebRTC
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import std/[openssl, os]
import posix
import chronos, chronicles
import stew/[byteutils, ptrops]

export chronicles

logScope:
  topics = "webrtc dtls"

# Missing openssl procs things
const
  BIO_NOCLOSE = 0x0
  #BIO_CLOSE   = 0x1
  BIO_CTRL_DGRAM_SET_CONNECTED = 32
  BIO_CTRL_DGRAM_GET_PEER = 46
  DTLS_CTRL_GET_TIMEOUT = 73
  BIO_C_SET_FD = 104

proc DTLS_client_method(): PSSL_METHOD {.cdecl, dynlib: DLLSSLName, importc.}
proc DTLS_server_method(): PSSL_METHOD {.cdecl, dynlib: DLLSSLName, importc.}
proc BIO_new_dgram(fd: SocketHandle, closeFlag: int): BIO {.cdecl, dynlib: DLLUtilName, importc.}
proc SSL_get_rbio(ssl: SslPtr): BIO {.cdecl, dynlib: DLLSSLName, importc.}
proc RAND_bytes(buf: pointer, length: int): int {.cdecl, dynlib: DLLSSLName, importc.}
proc DTLSv1_listen(ssl: SslPtr, peer: ptr): int {.cdecl, dynlib: DLLSSLName, importc.}
proc SSL_CTX_set_cookie_generate_cb(ctx: SslCtx, cb: proc (ssl: SslPtr, cookie: ptr byte, cookieLen: ptr int): int {.cdecl.}) {.cdecl, dynlib: DLLSSLName, importc.}
proc SSL_CTX_set_cookie_verify_cb(ctx: SslCtx, cb: proc (ssl: SslPtr, cookie: ptr byte, cookieLen: int): int {.cdecl.}) {.cdecl, dynlib: DLLSSLName, importc.}
# --- openssl

type
  DtlsSocket = ref object
    udp: DatagramTransport
    gotData: AsyncEvent
    sslCtx: SslCtx
    ctxIsView: bool
    ssl: SslPtr

proc waitForData(socket: DtlsSocket) {.async.} =
  socket.gotData.clear()
  var timeout: Timeval
  if (SSL_ctrl(socket.ssl, DTLS_CTRL_GET_TIMEOUT, 0, addr timeout) == 1):
    let
      momentTimeout = seconds(clong(timeout.tv_sec)) + nanoseconds(timeout.tv_usec)
      fut = socket.gotData.wait()
    if not await fut.withTimeout(momentTimeout):
      fut.cancel
  else:
    await socket.gotData.wait()

template wrapSslCallRes(dtlsSocket, call: untyped): untyped =
  block:
    var err: type(call)
    while true:
      err = call
      if err <= 0:
        let openSslErr = SSL_get_error(dtlsSocket.ssl, cint(err))
        if openSslErr in [SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE]:
          await dtlsSocket.waitForData()
          continue
        elif openSslErr == SSL_ERROR_SYSCALL:
          let err = osLastError()
          if cint(err) == EAGAIN:
            await dtlsSocket.waitForData()
            continue
          raiseTransportOsError(err)
        let errorMsg = ERR_error_string(culong(ERR_peek_last_error()), nil)
        raise ValueError.newException("openssl error: " & $errorMsg)
      break
    err

template wrapSslCall(dtlsSocket, call: untyped) =
  discard wrapSslCallRes(dtlsSocket, call)

proc fromSAddr(storeAddr: Sockaddr_storage): TransportAddress =
  let size =
    if int(storeAddr.ss_family) == ord(Domain.AF_INET):
       sizeof(Sockaddr_in)
    elif int(storeAddr.ss_family) == ord(Domain.AF_INET6):
       sizeof(Sockaddr_in6)
    elif int(storeAddr.ss_family) == ord(Domain.AF_UNIX):
       sizeof(Sockaddr_storage)
    else: -1
  fromSAddr(addr storeAddr, SockLen(size), result)

var cookieSecret: array[32, byte]
doAssert RAND_bytes(addr cookieSecret[0], cookieSecret.len) > 0

proc generateSslCookie(ssl: SslPtr, cookie: ptr byte, cookieLen: ptr int): int {.cdecl.} =
  var peerSockaddr: Sockaddr_storage
  if BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_GET_PEER, 0, cast[cstring](addr peerSockaddr)) <= 0:
    return 0

  let transportAddress = fromSAddr(peerSockaddr)
  if
      HMAC(EVP_sha1(),
      addr cookieSecret[0], cint(cookieSecret.len),
      cast[cstring](addr transportAddress), csize_t(sizeof(TransportAddress)),
      cast[cstring](cookie), cast[ptr cuint](cookieLen)) == nil:
    0
  else:
    1

proc verifySslCookie(ssl: SslPtr, cookie: ptr byte, cookieLen: int): int {.cdecl.} =
  var peerSockaddr: Sockaddr_storage
  if BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_GET_PEER, 0, cast[cstring](addr peerSockaddr)) <= 0:
    return 0

  let transportAddress = fromSAddr(peerSockaddr)
  var
    buffer: array[1024, byte]
    bufferLength: cuint
  if
      HMAC(EVP_sha1(),
      addr cookieSecret[0], cint(cookieSecret.len),
      cast[cstring](addr transportAddress), csize_t(sizeof(TransportAddress)),
      cast[cstring](addr buffer[0]), addr bufferLength) == nil:
    return 0

  if bufferLength != cuint(cookieLen): return 0
  if cookie.makeOpenArray(byte, cookieLen) == buffer[0 ..< bufferLength]:
    1
  else:
    0

proc createDtlsSocket(
  localAddress = AnyAddress,
  remoteAddress = AnyAddress,
  flags: set[ServerFlags] = {NoAutoRead}): DtlsSocket =

  let gotData = newAsyncEvent()
  proc callback(transp: DatagramTransport, remote: TransportAddress) {.async.} = discard
  proc callback2(udata: pointer) =
    gotData.fire()
  let datagram = newDatagramTransport(
    callback,
    local = localAddress,
    remote = remoteAddress,
    flags = flags)
  addReader(datagram.fd, callback2)
  return DtlsSocket(udp: datagram, gotData: gotData)


proc createDtlsServer*(host: TransportAddress): Future[DtlsSocket] {.async.} =
  result = createDtlsSocket(
    localAddress = host,
    flags = {NoAutoRead, ReuseAddr}
  )

  result.sslCtx = SSL_CTX_new(DTLS_server_method())
  #TODO if we close the server with connections alive,
  #they have a ref to this ctx

  #TODO handle certificates
  echo SSL_CTX_use_certificate_file(result.sslCtx, "certs/server-cert.pem", SSL_FILETYPE_PEM)
  echo SSL_CTX_use_PrivateKey_file(result.sslCtx, "certs/server-key.pem", SSL_FILETYPE_PEM)
  SSL_CTX_set_cookie_generate_cb(result.sslCtx, generateSslCookie)
  SSL_CTX_set_cookie_verify_cb(result.sslCtx, verifySslCookie)

proc accept*(sock: DtlsSocket): Future[DtlsSocket] {.async.} =
  let
    ctx = sock.sslCtx
    ssl = SSL_new(ctx)
    bio = BIO_new_dgram(SocketHandle(sock.udp.fd), BIO_NOCLOSE)

  sslSetBio(ssl, bio, bio)

  var clientSockAddr: Sockaddr_storage
  doAssert isNil(sock.ssl)
  sock.ssl = ssl
  wrapSslCall(sock, DTLSv1_listen(ssl, addr clientSockAddr))
  sock.ssl = nil
  let clientAddr = fromSAddr(clientSockAddr)

  # create new socket
  result = createDtlsSocket(
    localAddress = sock.udp.localAddress,
    remoteAddress = clientAddr,
    flags = {NoAutoRead, ReuseAddr}
  )

  let sockHandle = SocketHandle(result.udp.fd)
  doAssert BIO_ctrl(bio, BIO_C_SET_FD, 0, cast[cstring](addr sockHandle)) > 0
  doAssert BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, cast[cstring](addr clientSockAddr)) > 0

  result.sslCtx = ctx
  result.ssl = ssl
  result.ctxIsView = true
  wrapSslCall(result, SSL_accept(ssl))

proc connect*(address: TransportAddress): Future[DtlsSocket] {.async.} =
  result = createDtlsSocket(
    remoteAddress = address
  )

  let
    ctx = SSL_CTX_new(DTLS_client_method())
    ssl = SSL_new(ctx)
    bio = BIO_new_dgram(SocketHandle(result.udp.fd), BIO_NOCLOSE)

  #TODO handle certs
  echo SSL_CTX_use_certificate_file(ctx, "certs/client-cert.pem", SSL_FILETYPE_PEM)
  echo SSL_CTX_use_PrivateKey_file(ctx, "certs/client-key.pem", SSL_FILETYPE_PEM)
  echo SSL_CTX_check_private_key(ctx)

  result.sslCtx = ctx
  result.ssl = ssl
  var slen: SockLen
  var remoteSaddr: Sockaddr_storage
  toSAddr(address, remoteSaddr, slen)
  doAssert BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, cast[cstring](addr remoteSaddr)) > 0
  sslSetBio(ssl, bio, bio)
  wrapSslCall(result, SSL_connect(ssl))

proc write*(sock: DtlsSocket, data: seq[byte]) {.async.} =
  wrapSslCall(sock, SSL_write(sock.ssl, cast[cstring](addr data[0]), data.len))

proc read*(sock: DtlsSocket): Future[seq[byte]] {.async.} =
  result = newSeq[byte](1000)
  let length = wrapSslCallRes(sock, SSL_read(sock.ssl, cast[cstring](addr result[0]), result.len))
  result.setLen(length)

proc close*(sock: DtlsSocket) {.async.} =
  if not isNil(sock.ssl):
    let shutdownRes = SSL_shutdown(sock.ssl)
    if shutdownRes == 0:
      wrapSslCall(sock, SSL_shutdown(sock.ssl))
    SSL_free(sock.ssl)
  if not isNil(sock.sslCtx) and not sock.ctxIsView:
    SSL_CTX_free(sock.sslCtx)
  sock.udp.close()

proc main {.async.} =
  let
    address = initTAddress("127.0.0.1:8090")
    server = await createDtlsServer(address)
    client = connect(address)

  let
    servConn = await server.accept()
    clientConn = await client
  await clientConn.write("Hello world!".toBytes())
  echo string.fromBytes(await servConn.read())

  await allFutures(servConn.close(), clientConn.close())
  await server.close()

waitFor(main())
