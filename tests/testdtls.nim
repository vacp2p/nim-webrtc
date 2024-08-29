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
import ../webrtc/dtls/dtls_connection
import ./asyncunit

suite "DTLS":
  teardown:
    checkLeaks()

  asyncTest "Two DTLS nodes connecting to each other, then sending/receiving data":
    let
      localAddr1 = initTAddress("127.0.0.1:4444")
      localAddr2 = initTAddress("127.0.0.1:5555")
      udp1 = UdpTransport.new(localAddr1)
      udp2 = UdpTransport.new(localAddr2)
      stun1 = Stun.new(udp1)
      stun2 = Stun.new(udp2)
      dtls1 = Dtls.new(stun1)
      dtls2 = Dtls.new(stun2)
      conn1Fut = dtls1.accept()
      conn2 = await dtls2.connect(localAddr1)
      conn1 = await conn1Fut

    await conn1.write(@[1'u8, 2, 3, 4])
    let seq1 = await conn2.read()
    check seq1 == @[1'u8, 2, 3, 4]

    await conn2.write(@[5'u8, 6, 7, 8])
    let seq2 = await conn1.read()
    check seq2 == @[5'u8, 6, 7, 8]
    await allFutures(conn1.close(), conn2.close())
    await allFutures(dtls1.stop(), dtls2.stop())
    await allFutures(stun1.stop(), stun2.stop())
    await allFutures(udp1.close(), udp2.close())

  asyncTest "Two DTLS nodes connecting to the same DTLS server, sending/receiving data":
    let
      localAddr1 = initTAddress("127.0.0.1:4444")
      localAddr2 = initTAddress("127.0.0.1:5555")
      localAddr3 = initTAddress("127.0.0.1:6666")
      udp1 = UdpTransport.new(localAddr1)
      udp2 = UdpTransport.new(localAddr2)
      udp3 = UdpTransport.new(localAddr3)
      stun1 = Stun.new(udp1)
      stun2 = Stun.new(udp2)
      stun3 = Stun.new(udp3)
      dtls1 = Dtls.new(stun1)
      dtls2 = Dtls.new(stun2)
      dtls3 = Dtls.new(stun3)
      servConn1Fut = dtls1.accept()
      servConn2Fut = dtls1.accept()
      clientConn1 = await dtls2.connect(localAddr1)
      clientConn2 = await dtls3.connect(localAddr1)
      servConn1 = await servConn1Fut
      servConn2 = await servConn2Fut

    await servConn1.write(@[1'u8, 2, 3, 4])
    await servConn2.write(@[5'u8, 6, 7, 8])
    await clientConn1.write(@[9'u8, 10, 11, 12])
    await clientConn2.write(@[13'u8, 14, 15, 16])
    check:
      (await clientConn1.read()) == @[1'u8, 2, 3, 4]
      (await clientConn2.read()) == @[5'u8, 6, 7, 8]
      (await servConn1.read()) == @[9'u8, 10, 11, 12]
      (await servConn2.read()) == @[13'u8, 14, 15, 16]
    await allFutures(servConn1.close(), servConn2.close())
    await allFutures(clientConn1.close(), clientConn2.close())
    await allFutures(dtls1.stop(), dtls2.stop(), dtls3.stop())
    await allFutures(stun1.stop(), stun2.stop(), stun3.stop())
    await allFutures(udp1.close(), udp2.close(), udp3.close())

  asyncTest "Two DTLS nodes connecting to each other, disconnecting and reconnecting":
    let
      localAddr1 = initTAddress("127.0.0.1:4444")
      localAddr2 = initTAddress("127.0.0.1:5555")
      udp1 = UdpTransport.new(localAddr1)
      udp2 = UdpTransport.new(localAddr2)
      stun1 = Stun.new(udp1)
      stun2 = Stun.new(udp2)
      dtls1 = Dtls.new(stun1)
      dtls2 = Dtls.new(stun2)
    var
      conn1Fut = dtls1.accept()
      conn2 = await dtls2.connect(localAddr1)
      conn1 = await conn1Fut

    await conn1.write(@[1'u8, 2, 3, 4])
    await conn2.write(@[5'u8, 6, 7, 8])
    check (await conn1.read()) == @[5'u8, 6, 7, 8]
    check (await conn2.read()) == @[1'u8, 2, 3, 4]
    await allFutures(conn1.close(), conn2.close())

    conn1Fut = dtls1.accept()
    conn2 = await dtls2.connect(localAddr1)
    conn1 = await conn1Fut

    await conn1.write(@[5'u8, 6, 7, 8])
    await conn2.write(@[1'u8, 2, 3, 4])
    check (await conn1.read()) == @[1'u8, 2, 3, 4]
    check (await conn2.read()) == @[5'u8, 6, 7, 8]

    await allFutures(conn1.close(), conn2.close())
    await allFutures(dtls1.stop(), dtls2.stop())
    await allFutures(stun1.stop(), stun2.stop())
    await allFutures(udp1.close(), udp2.close())
