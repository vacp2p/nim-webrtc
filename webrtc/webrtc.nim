# Nim-WebRTC
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import chronos, chronicles

import udp_connection
import stun/stun_connection
import dtls/dtls
import sctp, datachannel

logScope:
  topics = "webrtc"

type
  WebRTC* = ref object
    udp*: UdpConn
    stun*: StunConn
    dtls*: Dtls
    sctp*: Sctp
    port: int

proc dtlsLocalCertificate(w: WebRTC): seq[byte] =
  w.dtls.localCertificate()

proc new*(T: typedesc[WebRTC], address: TransportAddress): T =
  var webrtc = T(udp: UdpConn(), stun: StunConn(), dtls: Dtls())
  webrtc.udp.init(address)
  webrtc.stun.init(webrtc.udp, address)
  webrtc.dtls.start(webrtc.stun, address)
  webrtc.sctp = Sctp.new(webrtc.dtls, address)
  return webrtc

proc listen*(w: WebRTC) =
  w.sctp.listen()

proc accept*(w: WebRTC): Future[DataChannelConnection] {.async.} =
  let sctpConn = await w.sctp.accept()
  result = DataChannelConnection.new(sctpConn)
