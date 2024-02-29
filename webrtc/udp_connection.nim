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

# UdpConn is a small wrapper of the chronos DatagramTransport.
# It's the simplest solution we found to store the message and
# the remote address used by the underlying protocols (dtls/sctp etc...)

type
  UdpConn* = ref object
    laddr*: TransportAddress
    udp: DatagramTransport
    dataRecv: AsyncQueue[(seq[byte], TransportAddress)]
    closed: bool

proc init*(self: UdpConn, laddr: TransportAddress) =
  self.laddr = laddr
  self.closed = false

  proc onReceive(udp: DatagramTransport, address: TransportAddress) {.async, gcsafe.} =
    trace "UDP onReceive"
    let msg = udp.getMessage()
    self.dataRecv.addLastNoWait((msg, address))

  self.dataRecv = newAsyncQueue[(seq[byte], TransportAddress)]()
  self.udp = newDatagramTransport(onReceive, local = laddr)

proc close*(self: UdpConn) {.async.} =
  if self.closed:
    debug "Try to close UdpConn twice"
    return
  self.closed = true
  self.udp.close()

proc write*(self: UdpConn, raddr: TransportAddress, msg: seq[byte]) {.async.} =
  if self.closed:
    debug "Try to write on an already closed UdpConn"
    return
  trace "UDP write", msg
  await self.udp.sendTo(raddr, msg)

proc read*(self: UdpConn): Future[(seq[byte], TransportAddress)] {.async.} =
  if self.closed:
    debug "Try to read on an already closed UdpConn"
    return
  trace "UDP read"
  return await self.dataRecv.popFirst()
