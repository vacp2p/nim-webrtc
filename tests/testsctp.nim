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

  asyncTest "Two SCTP nodes connecting to each other, then sending/receiving data":
    let
      localAddr1 = initTAddress("127.0.0.1:4444")
      localAddr2 = initTAddress("127.0.0.1:5555")
      udp1 = UdpTransport.new(localAddr1)
      udp2 = UdpTransport.new(localAddr2)
      stun1 = Stun.new(udp1)
      stun2 = Stun.new(udp2)
      dtls1 = Dtls.new(stun1)
      dtls2 = Dtls.new(stun2)
      sctp1 = Sctp.new(dtls1)
      sctp2 = Sctp.new(dtls2)
    sctp1.listen()
    let conn1Fut = sctp1.accept()
    let conn2 = await sctp2.connect(localAddr1)
    let conn1 = await conn1Fut

    await conn1.write(@[1'u8, 2, 3, 4])
    check (await conn2.read()).data == @[1'u8, 2, 3, 4]

    await conn2.write(@[5'u8, 6, 7, 8])
    check (await conn1.read()).data == @[5'u8, 6, 7, 8]

    await conn1.write(@[10'u8, 11, 12, 13])
    await conn2.write(@[14'u8, 15, 16, 17])
    check (await conn1.read()).data == @[14'u8, 15, 16, 17]
    check (await conn2.read()).data == @[10'u8, 11, 12, 13]

    await allFutures(conn1.close(), conn2.close())
    await allFutures(sctp1.close(), sctp2.close())
    await allFutures(dtls1.stop(), dtls2.stop())
    await allFutures(stun1.stop(), stun2.stop())
    await allFutures(udp1.close(), udp2.close())
