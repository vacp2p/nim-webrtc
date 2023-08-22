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
  UdpConn* = ref object of WebRTCConn
    udp: DatagramTransport
    recvData: seq[seq[byte]]
    recvEvent: AsyncEvent

method init(self: UdpConn, conn: WebRTCConn, address: TransportAddress) {.async.} =
  await procCall(WebRTCConn(self).init(conn, address))

  proc onReceive(udp: DatagramTransport, address: TransportAddress) {.async, gcsafe.} =
    let msg = udp.getMessage()
    self.recvData.add(msg)
    self.recvEvent.fire()

  self.recvEvent = newAsyncEvent()
  self.udp = newDatagramTransport(onReceive, local = address)

method close(self: UdpConn) {.async.} =
  self.udp.close()
  if not self.conn.isNil():
    await self.conn.close()

method write(self: UdpConn, msg: seq[byte]) {.async.} =
  await self.udp.sendTo(self.address, msg)

method read(self: UdpConn): Future[seq[byte]] {.async.} =
  while self.recvData.len() <= 0:
    self.recvEvent.clear()
    await self.recvEvent.wait()
  result = self.recvData[0]
  self.recvData.delete(0..0)
