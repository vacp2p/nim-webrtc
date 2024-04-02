# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import chronos, chronicles
import ../udp_connection, stun

logScope:
  topics = "webrtc stun"

# TODO:
# - Work fine when behaves like a server, need to implement the client side
#   It needs a bit of a rework on the Stun object such as:
#   - Add a connect/accept couple
#   - Add a ping/pong (more like BindingRequest/BindingResponse) by remote address
#   - Need to implement ICE-CONTROLL(ED|ING) for browser to browser (not critical)

type
  StunConn* = ref object
    conn: UdpConn
    laddr: TransportAddress
    dataRecv: AsyncQueue[UdpPacketInfo]
    handlesFut: Future[void]
    closed: bool

proc handles(self: StunConn) {.async: (raises: [CancelledError]).} =
  # Infinite read loop. When the message is a Stun Message, it returns the
  # correct acknowledgement. When the message isn't a Stun Message, it is
  # stored until it is read.
  while true:
    let packetInfo = await self.conn.read()
    if Stun.isMessage(packetInfo.message):
      let res = Stun.getPong(packetInfo.message, self.laddr)
      if res.isSome():
        try:
          await self.conn.write(packetInfo.raddr, res.get())
        except WebRtcUdpError as exc:
          trace "Failed to write the Stun response", error=exc.msg
          continue
    else:
      self.dataRecv.addLastNoWait(packetInfo)

proc init*(T: type StunConn, conn: UdpConn, laddr: TransportAddress): T =
  ## Initialize a Stun Connection
  ##
  var self = T()
  self.conn = conn
  self.laddr = laddr
  self.closed = false
  self.dataRecv = newAsyncQueue[UdpPacketInfo]()
  self.handlesFut = self.handles()
  return self

proc close*(self: StunConn) =
  ## Close a Stun Connection
  ##
  if self.closed:
    debug "Try to close an already closed StunConn"
    return
  self.closed = true
  self.handlesFut.cancel()
  self.conn.close()

proc write*(
    self: StunConn,
    raddr: TransportAddress,
    msg: seq[byte]
  ) {.async: (raises: [CancelledError, WebRtcUdpError].} =
  ## Write a message on Udp to a remote `raddr` using
  ## the underlying Udp Connection
  ##
  if self.closed:
    debug "Try to write on an already closed StunConn"
    return
  await self.conn.write(raddr, msg)

proc read*(self: StunConn): Future[UdpPacketInfo] {.async: (raises: [CancelledError]).} =
  ## Read the next received non-Stun Message
  ##
  if self.closed:
    debug "Try to read on an already closed StunConn"
    return
  return await self.dataRecv.popFirst()
