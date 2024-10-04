# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import chronos, chronicles

import udp_transport
import stun/stun_transport
import dtls/dtls_transport
import sctp/sctp_transport
import datachannel
import errors

logScope:
  topics = "webrtc"

type WebRTC* = ref object
  udp: UdpTransport
  stun: Stun
  dtls: Dtls
  sctp: Sctp
  port: int

proc new*(T: typedesc[WebRTC], address: TransportAddress): T =
  result = T()
  result = UdpTransport.new(address)
  result = Stun.new(result.udp)
  result = Dtls.new(result.stun)
  result = Sctp.new(result.dtls)

proc listen*(self: WebRTC) =
  self.sctp.listen()

proc connect*(
    self: WebRTC, raddr: TransportAddress
): Future[DataChannelConnection] {.async: (raises: [CancelledError, WebRtcError]).} =
  let sctpConn = await self.sctp.connect(raddr) # TODO: Port?
  result = DataChannelConnection.new(sctpConn)

proc accept*(
    w: WebRTC
): Future[DataChannelConnection] {.async: (raises: [CancelledError, WebRtcError]).} =
  let sctpConn = await w.sctp.accept()
  result = DataChannelConnection.new(sctpConn)
