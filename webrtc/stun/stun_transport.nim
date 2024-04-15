# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import tables
import chronos, chronicles, bearssl
import stun_connection, stun_protocol, ../udp_connection

logScope:
  topics = "webrtc stun stun_transport"

type
  Stun* = ref object
    connections: Table[TransportAddress, StunConn]
    pendingConn: AsyncQueue[StunConn]
    readingLoop: Future[void]
    conn: UdpConn
    iceTiebreaker: uint64
    rng: ref HmacDrbgContext

proc accept*(self: Stun): Future[StunConn] {.async.} =
  ## Accept a Stun Connection
  ##
  var res: StunConn
  while true:
    res = await self.pendingConn.popFirst()
    if res.closed != true: # The connection could be closed before being accepted
      break
  return res

proc connect*(self: Stun, raddr: TransportAddress): Future[StunConn] {.async.} =
  ## Connect to a remote address, creating a Stun Connection
  ##
  if self.connections.hasKey(raddr):
    return self.connections[raddr]
  var res = StunConn.init(self.conn, raddr, false)
  self.connections[raddr] = res
  return res

proc cleanupStunConn(self: Stun, conn: StunConn) {.async: (raises: []).} =
  # Waiting for a connection to be closed to remove it from the table
  try:
    await conn.join()
    self.connections.del(conn.raddr)
  except CancelledError as exc:
    warn "Error cleaning up Stun Connection", error=exc.msg

proc stunReadLoop(self: Stun) {.async.} =
  while true:
    let (buf, raddr) = await self.conn.read()
    let stunConn =
      if not self.connections.hasKey(raddr):
        let res = StunConn.init(self.conn, raddr, true)
        self.connections[raddr] = res
        self.pendingConn.addLastNoWait(res)
        asyncSpawn self.cleanupStunConn(res)
        res
      else:
        self.connections[raddr]

    if isStunMessage(buf):
      stunConn.stunMsgs.addLastNoWait(buf)
    else:
      stunConn.dataRecv.addLastNoWait(buf)

proc stop(self: Stun) =
  ## Stop the Stun transport and close all the connections
  ##
  for conn in self.connections.values():
    conn.close()
  self.readingLoop.cancelSoon()

proc init*(
    T: type Stun,
    conn: UdpConn,
    rng: ref HmacDrbgContext = HmacDrbgContext.new()
  ): T =
  ## Initialize the Stun transport
  ##
  var self = T(conn: conn, rng: rng)
  self.rng.generate(self.iceTieBreaker)
  self.readingLoop = stunReadLoop()
  return self