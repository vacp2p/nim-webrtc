# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import bearssl, chronos, chronicles

import udp_transport
import stun/stun_transport
import dtls/dtls_transport
import sctp/sctp_transport
import datachannel
import errors

from stun/stun_connection import StunUsernameProvider, StunUsernameChecker, StunPasswordProvider

logScope:
  topics = "webrtc"

type WebRTC* = ref object
  udp: UdpTransport
  stun: Stun
  dtls: Dtls
  sctp: Sctp
  port: int

proc new*(T: typedesc[WebRTC], address: TransportAddress,
    usernameProvider: StunUsernameProvider = defaultUsernameProvider,
    usernameChecker: StunUsernameChecker = defaultUsernameChecker,
    passwordProvider: StunPasswordProvider = defaultPasswordProvider,
  ): T =
  result = T()
  result.udp = UdpTransport.new(address)
  result.stun = Stun.new(result.udp, usernameProvider, usernameChecker, passwordProvider)
  result.dtls = Dtls.new(result.stun)
  result.sctp = Sctp.new(result.dtls)

proc listen*(self: WebRTC) =
  self.sctp.listen()

proc connect*(
    self: WebRTC, raddr: TransportAddress
): Future[DataChannelConnection] {.async: (raises: [CancelledError, WebRtcError]).} =
  let sctpConn = await self.sctp.connect(raddr)
  result = DataChannelConnection.new(sctpConn, false)

proc accept*(
    self: WebRTC
): Future[DataChannelConnection] {.async: (raises: [CancelledError, WebRtcError]).} =
  let sctpConn = await self.sctp.accept()
  result = DataChannelConnection.new(sctpConn, true)

proc localCertificate*(self: WebRTC): seq[byte] =
  self.dtls.localCertificate()

proc localAddress*(self: WebRTC): TransportAddress =
  self.udp.laddr
