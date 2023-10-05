# Nim-WebRTC
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import chronos
import ../webrtc_connection, stun

type
  StunConn* = ref object of WebRTCConn
    recvData: seq[seq[byte]]
    recvEvent: AsyncEvent
    handlesFut: Future[void]

proc handles(self: StunConn) {.async.} =
  while true: # TODO: while not self.conn.atEof()
    let msg = await self.conn.read()
    if Stun.isMessage(msg):
      let res = Stun.getResponse(msg, self.address)
      if res.isSome():
        await self.conn.write(res.get())
    else:
      self.recvData.add(msg)
      self.recvEvent.fire()

method init(self: StunConn, conn: WebRTCConn, address: TransportAddress) {.async.} =
  await procCall(WebRTCConn(self).init(conn, address))

  self.recvEvent = newAsyncEvent()
  self.handlesFut = handles()

method close(self: StunConn) {.async.} =
  self.handlesFut.cancel() # check before?
  self.conn.close()

method write(self: StunConn, msg: seq[byte]) {.async.} =
  await self.conn.write(msg)

method read(self: StunConn): Future[seq[byte]] {.async.} =
  while self.recvData.len() <= 0:
    self.recvEvent.clear()
    await self.recvEvent.wait()
  result = self.recvData[0]
  self.recvData.delete(0..0)

method getRemoteAddress*(self: StunConn): TransportAddress =
  self.conn.getRemoteAddress()
