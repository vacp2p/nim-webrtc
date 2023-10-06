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
import webrtc_connection

logScope:
  topics = "webrtc udp"

type
  UdpConn* = ref object
    laddr: TransportAddress
    udp: DatagramTransport
    dataRecv: AsyncQueue[(seq[byte], TransportAddress)]

proc init(self: UdpConn, laddr: TransportAddress) {.async.} =
  self.laddr = laddr

  proc onReceive(udp: DatagramTransport, address: TransportAddress) {.async, gcsafe.} =
    let msg = udp.getMessage()
    echo "\e[33m<UDP>\e[0;1m onReceive\e[0m: ", msg.len()
    self.dataRecv.addLastNoWait((msg, address))

  self.dataRecv = newAsyncQueue()
  self.udp = newDatagramTransport(onReceive, local = laddr)

proc close(self: UdpConn) {.async.} =
  self.udp.close()
  if not self.conn.isNil():
    await self.conn.close()

proc write(self: UdpConn, msg: seq[byte]) {.async.} =
  echo "\e[33m<UDP>\e[0;1m write\e[0m"
  await self.udp.sendTo(self.remote, msg)

proc read(self: UdpConn): Future[(seq[byte], TransportAddress)] {.async.} =
  echo "\e[33m<UDP>\e[0;1m read\e[0m"
  return await self.dataRecv.popFirst()
