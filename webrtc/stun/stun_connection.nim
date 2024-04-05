# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import chronos, chronicles
import ../udp_connection, stun_protocol

logScope:
  topics = "webrtc stun"

# TODO:
# - Work fine when behaves like a server, need to implement the client side
#   It needs a bit of a rework on the Stun object such as:
#   - Add a connect/accept couple
#   - Add a ping/pong (more like BindingRequest/BindingResponse) by remote address
#   - Need to implement ICE-CONTROLL(ED|ING) for browser to browser (not critical)

type
  StunConn* = ref object
    conn*: UdpConn
    laddr*: TransportAddress
    raddr*: TransportAddress
    dataRecv*: AsyncQueue[seq[byte]]
    stunMsgs*: AsyncQueue[seq[byte]]
    handlesFut*: Future[void]
    closed*: bool

# - Stun Messages Handler -
# Read indefinitely Stun message and send a BindingResponse when receiving a
# BindingRequest. It should work on a Browser to Server or Server to Server cases.
# On the case of Browser to Browser, the ICE protocol will probably need to be
# implemented, hence the name of the two handlers and the similar code.

proc iceControlledHandles(self: StunConn) {.async: (raises: [CancelledError]).} =
  while true:
    let
      message = await self.stunMsgs.popFirst()
      res = getBindingResponse(message, self.laddr)
    if res.isSome():
      try:
        await self.conn.write(self.raddr, res.get())
      except WebRtcUdpError as exc:
        trace "Failed to write the Stun response", error=exc.msg
        continue

proc iceControllingHandles(self: StunConn) {.async: (raises: [CancelledError]).} =
  while true:
    let
      message = await self.stunMsgs.popFirst()
      res = getBindingResponse(message, self.laddr)
    if res.isSome():
      try:
        await self.conn.write(self.raddr, res.get())
      except WebRtcUdpError as exc:
        trace "Failed to write the Stun response", error=exc.msg
        continue

proc init*(
    T: type StunConn,
    conn: UdpConn,
    raddr: TransportAddress,
    isServer: bool
  ): T =
  ## Initialize a Stun Connection
  ##
  var self = T()
  self.conn = conn
  self.laddr = conn.laddr
  self.raddr = raddr
  self.closed = false
  self.dataRecv = newAsyncQueue[seq[byte]]()
  self.stunMsgs = newAsyncQueue[seq[byte]]()
  if isServer:
    self.handlesFut = self.iceControllingHandles()
  else:
    self.handlesFut = self.iceControlledHandles()
  return self

proc close*(self: StunConn) =
  ## Close a Stun Connection
  ##
  if self.closed:
    debug "Try to close an already closed StunConn"
    return
  self.closed = true
  self.handlesFut.cancelSoon()
  self.conn.close()

proc write*(
    self: StunConn,
    raddr: TransportAddress,
    msg: seq[byte]
  ) {.async: (raises: [CancelledError, WebRtcUdpError]).} =
  ## Write a message on Udp to a remote `raddr` using
  ## the underlying Udp Connection
  ##
  if self.closed:
    debug "Try to write on an already closed StunConn"
    return
  await self.conn.write(raddr, msg)

proc read*(self: StunConn): Future[UdpPacketInfo] {.async: (raises: [CancelledError]).} =
  ## Read the next received non-Stun Message
  ##
  if self.closed:
    debug "Try to read on an already closed StunConn"
    return
  return (await self.dataRecv.popFirst(), self.raddr)
