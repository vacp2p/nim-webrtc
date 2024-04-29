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
import ../[udp_connection, errors], stun_message, stun_attributes, stun_utils

logScope:
  topics = "webrtc stun stun_connection"

# TODO:
# - Need to implement ICE-CONTROLL(ED|ING) for browser to browser (not critical)

const
  StunBindingRequest* = 0x0001'u16
  StunBindingResponse* = 0x0101'u16
  StunBindingErrorResponse* = 0x0111'u16

type
  StunConn* = ref object
    conn*: UdpConn # Underlying UDP connexion
    laddr*: TransportAddress # Local address
    raddr*: TransportAddress # Remote address
    dataRecv*: AsyncQueue[seq[byte]] # data received which will be read by DTLS
    stunMsgs*: AsyncQueue[seq[byte]] # stun messages received and to be
                                     # processed by the stun message handler
    handlesFut*: Future[void] # Stun Message handler
    closeEvent: AsyncEvent
    closed*: bool

    # Is ice-controlling and iceTiebreaker, not fully implemented yet.
    iceControlling: bool
    iceTiebreaker: uint32

    rng: ref HmacDrbgContext

# - Create Binding Messages (Request / Response / Error)

proc getBindingResponse*(self: StunConn, msg: StunMessage): StunMessage =
  ## Takes an encoded Stun Message and the local address. Returns
  ## an encoded Binding Response if the received message is a
  ## Binding request.
  ##
  result = StunMessage(msgType: StunBindingResponse,
                        transactionId: msg.transactionId)
  result.attributes.add(XorMappedAddress.encode(self.raddr, msg.transactionId))

proc calculatePriority(self: StunConn): uint32 =
  # https://datatracker.ietf.org/doc/html/rfc8445#section-5.1.2.1
  # Calculate Ice priority. At the moment, we assume we're a publicly available server.
  let typePreference = 126'u32
  let localPreference = 65535'u32
  let componentID = 1'u32
  return (1 shl 24) * typePreference + (1 shl 8) * localPreference + (256 - componentID)

proc getBindingRequest*(self: StunConn, username: string = ""): StunMessage =
  ## Creates an encoded Binding Request
  ##
  result = StunMessage(msgType: StunBindingRequest)
  self.rng[].generate(result.transactionId)

  if username.len() == 0:
    let ufrag = string.fromBytes(self.rng.genUfrag(32))
    let p2pUsername = "libp2p+webrtc+v1/" & ufrag
    result.attributes.add(UsernameAttribute.encode(p2pUsername & ":" & p2pUsername))
  else:
    result.attributes.add(UsernameAttribute.encode(username))

  if self.iceControlling:
    result.attributes.add(IceControlling.encode(self.iceTiebreaker))
  else:
    result.attributes.add(IceControlled.encode(self.iceTiebreaker))
  result.attributes.add(Priority.encode(self.calculatePriority()))

proc checkForError*(msg: StunMessage): Option[StunMessage] =
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
  let username = string.fromBytes(msg.getAttribute(AttrUsername).get().value)
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

proc stunMessageHandler(self: StunConn) {.async: (raises: [CancelledError]).} =
  # Read indefinitely Stun messages from stunMsgs queue.
  # Sends a BindingResponse or BindingResponseError after receiving a BindingRequest.
  while true:
    let message = await self.stunMsgs.popFirst()
    try:
      let decoded = StunMessage.decode(await self.stunMsgs.popFirst())
      if decoded.msgType == StunBindingErrorResponse:
        trace "Received a STUN error", decoded, remote = self.raddr
        continue
      elif decoded.msgType == StunBindingResponse:
        # TODO: Handle it
        continue
      else:
        let errorOpt = checkForError(decoded)
        if errorOpt.isSome():
          let error = errorOpt.get()
          await self.conn.write(self.raddr, error.encode())
          continue

        let bindingResponse = self.getBindingResponse(decoded)
        await self.conn.write(
          self.raddr,
          bindingResponse.encode(decoded.getAttribute(AttrUsername))
        )
    except SerializationError as exc:
      warn "Failed to decode the Stun message", error=exc.msg, message
    except WebRtcError as exc:
      trace "Failed to write the Stun response", error=exc.msg

proc init*(
    T: type StunConn,
    conn: UdpConn,
    raddr: TransportAddress,
    iceControlling: bool,
    rng: ref HmacDrbgContext
  ): T =
  ## Initialize a Stun Connection
  ##
  var self = T(
    conn: conn,
    laddr: conn.laddr,
    raddr: raddr,
    closed: false,
    closeEvent: newAsyncEvent(),
    dataRecv: newAsyncQueue[seq[byte]](),
    stunMsgs: newAsyncQueue[seq[byte]](),
    iceControlling: iceControlling,
    iceTiebreaker: rng[].generate(uint32),
    rng: rng
  )
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
