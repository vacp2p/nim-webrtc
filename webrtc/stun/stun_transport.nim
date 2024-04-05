# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import tables, bitops
import chronos, bearssl
import stun_connection, stun_protocol, ../udp_connection

type
  Stun* = ref object
    connections: Table[TransportAddress, StunConn]
    pendingConn: AsyncQueue[StunConn]
    readingLoop: Future[void]
    conn: UdpConn
    iceTiebreaker: uint64
    rng: ref HmacDrbgContext

proc isStunMessage(msg: seq[byte]): bool =
  msg.len >= stunMsgHeaderSize and
    msg[4..<8] == stunMagicCookieSeq and
    bitand(0xC0'u8, msg[0]) == 0'u8

proc accept(self: Stun): Future[StunConn] {.async.} =
  var res = await self.pendingConn.popFirst()
  return res

proc connect(self: Stun, raddr: TransportAddress): Future[StunConn] {.async.} =
  if self.connections.hasKey(raddr):
    return self.connections[raddr]
  var res = StunConn.init(self.conn, raddr, false)
  self.connections[raddr] = res
  return res

proc stunReadLoop(self: Stun) {.async.} =
  while true:
    let (buf, raddr) = await self.conn.read()
    let stunConn =
      if not self.connections.hasKey(raddr):
        let res = StunConn.init(self.conn, raddr, true)
        self.connections[raddr] = res
        self.pendingConn.addLastNoWait(res)
        res
      else:
        self.connections[raddr]

    if isStunMessage(buf):
      stunConn.stunMsgs.addLastNoWait(buf)
    else:
      stunConn.dataRecv.addLastNoWait(buf)

proc init*(
    T: type Stun,
    conn: UdpConn,
    rng: ref HmacDrbgContext = HmacDrbgContext.new()
  ): T =
  var self = T(conn: conn, rng: rng)
  self.rng.generate(self.iceTieBreaker)
  self.readLoop = stunReadLoop()
  return self
