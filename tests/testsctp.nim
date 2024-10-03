# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

{.used.}

import chronos
import ../webrtc/udp_transport
import ../webrtc/stun/stun_transport
import ../webrtc/dtls/dtls_transport
import ../webrtc/sctp/sctp_transport
import ../webrtc/sctp/sctp_connection
import ./asyncunit

suite "SCTP":
  teardown:
    checkLeaks()

  type
    SctpStackForTest = object
      localAddress: TransportAddress
      udp: UdpTransport
      stun: Stun
      dtls: Dtls
      sctp: Sctp

  proc initSctpStack(la: TransportAddress): SctpStackForTest =
    result.udp = UdpTransport.new(la)
    result.localAddress = result.udp.localAddress()
    result.stun = Stun.new(result.udp)
    result.dtls = Dtls.new(result.stun)
    result.sctp = Sctp.new(result.dtls)
    result.sctp.listen()

  proc closeSctpStack(self: SctpStackForTest) {.async: (raises: [CancelledError]).} =
    await self.sctp.stop()
    await self.dtls.stop()
    await self.stun.stop()
    await self.udp.close()

#  asyncTest "Two SCTP nodes connecting to each other, then sending/receiving data":
#    var
#      sctpServer = initSctpStack(initTAddress("127.0.0.1:0"))
#      sctpClient = initSctpStack(initTAddress("127.0.0.1:0"))
#    echo "Before Accept"
#    let serverConnFut = sctpServer.sctp.accept()
#    echo "Before Connect"
#    let clientConn = await sctpClient.sctp.connect(sctpServer.localAddress)
#    echo "Before await accept"
#    let serverConn = await serverConnFut
#    echo "Connected :tada:"
#
#    await clientConn.write(@[1'u8, 2, 3, 4])
#    check (await serverConn.read()).data == @[1'u8, 2, 3, 4]
#
#    await serverConn.write(@[5'u8, 6, 7, 8])
#    check (await clientConn.read()).data == @[5'u8, 6, 7, 8]
#
#    await clientConn.write(@[10'u8, 11, 12, 13])
#    await serverConn.write(@[14'u8, 15, 16, 17])
#    check (await clientConn.read()).data == @[14'u8, 15, 16, 17]
#    check (await serverConn.read()).data == @[10'u8, 11, 12, 13]
#
#    await allFutures(clientConn.close(), serverConn.close())
#    await allFutures(sctpClient.closeSctpStack(), sctpServer.closeSctpStack())

  asyncTest "Two DTLS nodes connecting to the same DTLS server, sending/receiving data":
    var
      sctpServer = initSctpStack(initTAddress("127.0.0.1:0"))
      sctpClient1 = initSctpStack(initTAddress("127.0.0.1:0"))
      sctpClient2 = initSctpStack(initTAddress("127.0.0.1:0"))
    let
      serverConn1Fut = sctpServer.sctp.accept()
      serverConn2Fut = sctpServer.sctp.accept()
      clientConn1 = await sctpClient1.sctp.connect(sctpServer.localAddress)
      clientConn2 = await sctpClient2.sctp.connect(sctpServer.localAddress)
      serverConn1 = await serverConn1Fut
      serverConn2 = await serverConn2Fut

    await serverConn1.write(@[1'u8, 2, 3, 4])
    await serverConn2.write(@[5'u8, 6, 7, 8])
    await clientConn1.write(@[9'u8, 10, 11, 12])
    await clientConn2.write(@[13'u8, 14, 15, 16])
    check:
      (await clientConn1.read()).data == @[1'u8, 2, 3, 4]
      (await clientConn2.read()).data == @[5'u8, 6, 7, 8]
      (await serverConn1.read()).data == @[9'u8, 10, 11, 12]
      (await serverConn2.read()).data == @[13'u8, 14, 15, 16]
    await allFutures(clientConn1.close(), serverConn1.close())

    await serverConn2.write(@[5'u8, 6, 7, 8])
    await clientConn2.write(@[13'u8, 14, 15, 16])
    check:
      (await clientConn2.read()).data == @[5'u8, 6, 7, 8]
      (await serverConn2.read()).data == @[13'u8, 14, 15, 16]
    await allFutures(clientConn2.close(), serverConn2.close())

    await allFutures(sctpClient1.closeSctpStack(),
                     sctpClient2.closeSctpStack(),
                     sctpServer.closeSctpStack())
