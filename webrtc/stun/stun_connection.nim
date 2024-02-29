# Nim-WebRTC
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import chronos
import ../udp_connection, stun

type
  StunConn* = ref object
    conn: UdpConn
    laddr: TransportAddress
    dataRecv: AsyncQueue[(seq[byte], TransportAddress)]
    handlesFut: Future[void]

proc handles(self: StunConn) {.async.} =
  while true:
    let (msg, raddr) = await self.conn.read()
    if Stun.isMessage(msg):
      let res = Stun.getResponse(msg, self.laddr)
      if res.isSome():
        await self.conn.write(raddr, res.get())
    else:
      self.dataRecv.addLastNoWait((msg, raddr))

proc init*(self: StunConn, conn: UdpConn, laddr: TransportAddress) =
  self.conn = conn
  self.laddr = laddr

  self.dataRecv = newAsyncQueue[(seq[byte], TransportAddress)]()
  self.handlesFut = self.handles()

proc close*(self: StunConn) {.async.} =
  self.handlesFut.cancel() # check before?
  await self.conn.close()

proc write*(self: StunConn, raddr: TransportAddress, msg: seq[byte]) {.async.} =
  await self.conn.write(raddr, msg)

proc read*(self: StunConn): Future[(seq[byte], TransportAddress)] {.async.} =
  return await self.dataRecv.popFirst()
