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
  while true: # TODO: while not self.conn.atEof()
    let (msg, address) = await self.conn.read()
    if Stun.isMessage(msg):
      let res = Stun.getResponse(msg, self.laddr)
      if res.isSome():
        await self.conn.write(res.get())
    else:
      self.dataRecv.addLastNoWait((msg, address))

proc init(self: StunConn, conn: UdpConn, laddr: TransportAddress) {.async.} =
  self.conn = conn
  self.laddr = laddr

  self.dataRecv = newAsyncQueue()
  self.handlesFut = handles()

proc close(self: StunConn) {.async.} =
  self.handlesFut.cancel() # check before?
  self.conn.close()

proc write(self: StunConn, msg: seq[byte]) {.async.} =
  await self.conn.write(msg)

proc read(self: StunConn): Future[(seq[byte], TransportAddress)] {.async.} =
  return await self.dataRecv.popFirst()
