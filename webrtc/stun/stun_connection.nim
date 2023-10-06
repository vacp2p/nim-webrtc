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
    address: TransportAddress
    recvData: seq[(seq[byte], TransportAddress)]
    recvEvent: AsyncEvent
    handlesFut: Future[void]

proc handles(self: StunConn) {.async.} =
  while true: # TODO: while not self.conn.atEof()
    let (msg, address) = await self.conn.read()
    if Stun.isMessage(msg):
      let res = Stun.getResponse(msg, self.address)
      if res.isSome():
        await self.conn.write(res.get())
    else:
      self.recvData.add((msg, address))
      self.recvEvent.fire()

method init(self: StunConn, conn: UdpConn, address: TransportAddress) {.async.} =
  self.conn = conn
  self.address = address

  self.recvEvent = newAsyncEvent()
  self.handlesFut = handles()

method close(self: StunConn) {.async.} =
  self.handlesFut.cancel() # check before?
  self.conn.close()

method write(self: StunConn, msg: seq[byte]) {.async.} =
  await self.conn.write(msg)

method read(self: StunConn): Future[(seq[byte], TransportAddress)] {.async.} =
  while self.recvData.len() <= 0:
    self.recvEvent.clear()
    await self.recvEvent.wait()
  let res = self.recvData[0]
  self.recvData.delete(0..0)
  return res
