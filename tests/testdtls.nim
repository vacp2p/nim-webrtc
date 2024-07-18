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

  asyncTest "Simple Test":
    let
      udp1 = UdpTransport.new(initTAddress("127.0.0.1:4444"))
      udp2 = UdpTransport.new(initTAddress("127.0.0.1:5555"))
      stun1 = Stun.new(udp1)
      stun2 = Stun.new(udp2)
      dtls1 = Dtls.new(stun1)
      dtls2 = Dtls.new(stun2)
      conn1Fut = dtls1.accept()
      conn2 = await dtls2.connect(dtls1.laddr)
      conn1 = await conn1Fut

    await conn1.write(@[1'u8, 2, 3, 4])
    let seq1 = await conn2.read()
    check seq1 == @[1'u8, 2, 3, 4]

    await conn2.write(@[5'u8, 6, 7, 8])
    let seq2 = await conn1.read()
    check seq2 == @[5'u8, 6, 7, 8]
    echo 1111
    await allFutures(conn1.close(), conn2.close())
    echo 2222
    await allFutures(dtls1.stop(), dtls2.stop())
    echo 3333
    stun1.stop()
    echo 4444
    stun2.stop()
    echo 5555
    await udp1.close()
    echo 6666
    await udp2.close()
    echo 7777
