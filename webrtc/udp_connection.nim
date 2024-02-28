# Nim-WebRTC
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import sequtils
import chronos, chronicles

logScope:
  topics = "webrtc udp"

type
  UdpConn* = ref object
    laddr*: TransportAddress
    udp: DatagramTransport
    dataRecv: AsyncQueue[(seq[byte], TransportAddress)]

proc init*(self: UdpConn, laddr: TransportAddress) =
  self.laddr = laddr

  proc onReceive(udp: DatagramTransport, address: TransportAddress) {.async, gcsafe.} =
    let msg = udp.getMessage()
    trace "UDP onReceive", msg
    self.dataRecv.addLastNoWait((msg, address))

  self.dataRecv = newAsyncQueue[(seq[byte], TransportAddress)]()
  self.udp = newDatagramTransport(onReceive, local = laddr)

proc close*(self: UdpConn) {.async.} =
  self.udp.close()

proc write*(self: UdpConn, raddr: TransportAddress, msg: seq[byte]) {.async.} =
  trace "UDP write", msg
  await self.udp.sendTo(raddr, msg)

proc read*(self: UdpConn): Future[(seq[byte], TransportAddress)] {.async.} =
  trace "UDP read"
  return await self.dataRecv.popFirst()
