# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import strutils
import bearssl, chronos, chronicles, stew/[objects, byteutils]
import ../[udp_connection, errors], stun_message, stun_attributes

logScope:
  topics = "webrtc stun stun_connection"

# TODO:
# - Need to implement ICE-CONTROLL(ED|ING) for browser to browser (not critical)

const
  StunBindingRequest = 0x0001'u16
  StunBindingResponse = 0x0101'u16
  StunBindingErrorResponse = 0x0111'u16

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
    iceTiebreaker: uint64
    rng: ref HmacDrbgContext

# - Create Binding Messages (Request / Response / Error)

proc getBindingResponse(self: StunConn, msg: StunMessage): StunMessage =
  ## Takes an encoded Stun Message and the local address. Returns
  ## an encoded Binding Response if the received message is a
  ## Binding request.
  ##
  var res = StunMessage(msgType: StunBindingResponse,
                        transactionId: msg.transactionId)
  res.attributes.add(XorMappedAddress.encode(self.raddr, msg.transactionId))
  return res

proc getBindingRequest(
    ta: TransportAddress,
    username: seq[byte] = @[],
    transactionId: array[12, byte],
    iceControlling: bool = true
  ): seq[byte] =
  ## Creates an encoded Binding Request
  ##
  var res = StunMessage(msgType: StunBindingRequest,
                        transactionId: transactionId)
  res.attributes.add(UsernameAttribute.encode(username))
 # if iceControlling:
 #   res.attributes.add(IceControlling.encode()) # TODO
 # else:
 #   res.attributes.add(IceControlled.encode()) # TODO
 # res.attributes.add(Priority.encode()) # TODO
  # return encode(...)
  discard

proc checkForError(msg: StunMessage): Option[StunMessage] =
  # Check for error from a BindingRequest message.
  # Returns an option with some BindingErrorResponse if there is an error.
  # Returns none otherwise.
  # https://datatracker.ietf.org/doc/html/rfc5389#section-10.1.2
  var res = StunMessage(msgType: StunBindingErrorResponse,
                        transactionId: msg.transactionId)
  if msg.getAttribute(AttrMessageIntegrity).isNone() or
     msg.getAttribute(AttrUsername).isNone():
    res.attributes.add(ErrorCode.encode(ECBadRequest))
    return some(res)

  # This check is related to the libp2p specification.
  # Might be interesting to add a customizable function check.
  let username = string.fromBytes(msg.getAttribute(AttrUsername).get())
  let usersplit = username.split(":")
  if usersplit.len() != 2 and not usersplit[0].startsWith("libp2p+webrtc+v1/"):
    res.attributes.add(ErrorCode.encode(ECUnauthorized))
    return some(res)

  # https://datatracker.ietf.org/doc/html/rfc5389#section-15.9
  var unknownAttr: seq[uint16]
  for attr in msg.attributes:
    let typ = attr.attributeType
    if typ.isRequired() and typ notin StunAttributeEnum:
      unknownAttr.add(typ)
  if unknownAttr.len() > 0:
    res.attributes.add(ErrorCode.encode(ECUnknownAttribute))
    res.attributes.add(UnknownAttribute.encode(unknownAttr))
    return some(res)

  return none(StunMessage)

# - Stun Messages Handler -
# Read indefinitely Stun message and send a BindingResponse when receiving a
# BindingRequest.

proc stunMessageHandler(self: StunConn) {.async: (raises: [CancelledError]).} =
  while true:
    let message = await self.stunMsgs.popFirst()
    try:
      let decoded = StunMessage.decode(await self.stunMsgs.popFirst())
      if decoded.msgType == StunBindingErrorResponse:
        trace "Received a STUN error", decoded, remote = self.raddr
        continue
      if decoded.msgType == StunBindingResponse:
        # TODO: Handle it
        continue
      let errorOpt = checkForError(decoded)
      if errorOpt.isSome():
        let error = errorOpt.get()
        await self.conn.write(self.raddr, error.encode())

      let bindingResponse = self.getBindingResponse(decoded)
      await self.conn.write(self.raddr, bindingResponse.encode(decoded.getAttribute(AttrUsername)))
    except SerializationError as exc:
      warn "Failed to decode the Stun message", error=exc.msg, message
    except WebRtcError as exc:
      trace "Failed to write the Stun response", error=exc.msg

proc init*(
    T: type StunConn,
    conn: UdpConn,
    raddr: TransportAddress,
    isServer: bool,
    rng: ref HmacDrbgContext
  ): T =
  ## Initialize a Stun Connection
  ##
  var self = T()
  self.conn = conn
  self.laddr = conn.laddr
  self.raddr = raddr
  self.rng = rng
  self.iceTiebreaker = self.rng[].generate(uint64)
  self.closed = false
  self.closeEvent = newAsyncEvent()
  self.dataRecv = newAsyncQueue[seq[byte]]()
  self.stunMsgs = newAsyncQueue[seq[byte]]()
  self.handlesFut = self.stunMessageHandler()
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
    msg: seq[byte]
  ) {.async: (raises: [CancelledError, WebRtcError]).} =
  ## Write a message on Udp to a remote `raddr` using
  ## the underlying Udp Connection
  ##
  if self.closed:
    debug "Try to write on an already closed StunConn"
    return
  await self.conn.write(self.raddr, msg)

proc read*(self: StunConn): Future[UdpPacketInfo] {.async: (raises: [CancelledError]).} =
  ## Read the next received non-Stun Message
  ##
  if self.closed:
    debug "Try to read on an already closed StunConn"
    return
  return (await self.dataRecv.popFirst(), self.raddr)
