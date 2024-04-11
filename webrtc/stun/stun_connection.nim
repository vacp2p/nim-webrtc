# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import chronos, chronicles
import stun_protocol, ../[udp_connection, errors]
import ../udp_connection, stun_protocol

logScope:
  topics = "webrtc stun stun_connection"

# TODO:
# - Need to implement ICE-CONTROLL(ED|ING) for browser to browser (not critical)

type
  StunConn* = ref object
    conn*: UdpConn
    laddr*: TransportAddress
    raddr*: TransportAddress
    dataRecv*: AsyncQueue[seq[byte]]
    stunMsgs*: AsyncQueue[seq[byte]]
    handlesFut*: Future[void]
    closeEvent: AsyncEvent
    closed*: bool

# - Stun Messages Handler -
# Read indefinitely Stun message and send a BindingResponse when receiving a
# BindingRequest. It should work on a Browser to Server or Server to Server cases.
# On the case of Browser to Browser, the ICE protocol will need to be
# implemented, hence the name of the two handlers. As the ICE is not implemented
# yet both code are similar.

proc iceControlledHandles(self: StunConn) {.async: (raises: [CancelledError]).} =
  while true:
    try:
      let
        message = await self.stunMsgs.popFirst()
        res = getBindingResponse(message, self.laddr)
      if res.isSome():
        await self.conn.write(self.raddr, res.get())
    except WebRtcError as exc:
      trace "Failed to write the Stun response", error=exc.msg

proc iceControllingHandles(self: StunConn) {.async: (raises: [CancelledError]).} =
  while true:
    try:
      let
        message = await self.stunMsgs.popFirst()
        res = getBindingResponse(message, self.laddr)
      if res.isSome():
        await self.conn.write(self.raddr, res.get())
    except WebRtcError as exc:
      trace "Failed to write the Stun response", error=exc.msg

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
  self.closeEvent = newAsyncEvent()
  self.dataRecv = newAsyncQueue[seq[byte]]()
  self.stunMsgs = newAsyncQueue[seq[byte]]()
  if isServer:
    self.handlesFut = self.iceControllingHandles()
  else:
    self.handlesFut = self.iceControlledHandles()
  return self

proc join*(self: StunConn) {.async: (raises: [CancelledError]).} =
  ## Wait for the Stun Connection to be closed
  ##
  await self.closeEvent.wait()

proc close*(self: StunConn) =
  ## Close a Stun Connection
  ##
  if self.closed:
    debug "Try to close an already closed StunConn"
    return
  self.closed = true
  self.closeEvent.fire()
  self.handlesFut.cancelSoon()

proc write*(
    self: StunConn,
    raddr: TransportAddress,
    msg: seq[byte]
  ) {.async: (raises: [CancelledError, WebRtcError]).} =
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
