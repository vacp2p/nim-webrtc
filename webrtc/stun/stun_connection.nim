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

# TODO: Work fine when behaves like a server, need to implement the client side

type
  StunConn* = ref object
    conn: UdpConn
    laddr: TransportAddress
    dataRecv: AsyncQueue[(seq[byte], TransportAddress)]
    handlesFut: Future[void]
    closed: bool

proc handles(self: StunConn) {.async.} =
  while true:
    let packetInfo = await self.conn.read()
    if Stun.isMessage(packetInfo.message):
      let res = Stun.getPong(packetInfo.message, self.laddr)
      if res.isSome():
        await self.conn.write(packetInfo.raddr, res.get())
    else:
      self.dataRecv.addLastNoWait(packetInfo)

proc dial(self: StunConn, raddr: TransportAddress) {.async.} =
  discard

proc init*(self: StunConn, conn: UdpConn, laddr: TransportAddress) =
  self.conn = conn
  self.laddr = laddr
  self.closed = false

  self.dataRecv = newAsyncQueue[UdpPacketInfo]()
  self.handlesFut = self.handles()

proc close*(self: StunConn) {.async.} =
  if self.closed:
    debug "Try to close an already closed StunConn"
    return
  self.handlesFut.cancel() # check before?
  await self.conn.close()

proc write*(self: StunConn, raddr: TransportAddress, msg: seq[byte]) {.async.} =
  if self.closed:
    debug "Try to write on an already closed StunConn"
    return
  await self.conn.write(raddr, msg)

proc read*(self: StunConn): Future[UdpPacketInfo] {.async.} =
  if self.closed:
    debug "Try to read on an already closed StunConn"
    return
  return await self.dataRecv.popFirst()
