# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

{.used.}

import options, strutils
import bearssl
import ../webrtc/udp_connection
import ../webrtc/stun/stun_connection
import ../webrtc/stun/stun_message
import ../webrtc/stun/stun_attributes
import ../webrtc/stun/stun_utils
import ./asyncunit

proc newRng(): ref HmacDrbgContext =
  HmacDrbgContext.new()

proc usernameProvEmpty(): string = ""
proc usernameProvTest(): string {.raises: [], gcsafe.} = "TestUsername"
proc usernameCheckTrue(username: seq[byte]): bool {.raises: [], gcsafe.} = true
proc usernameCheckFalse(username: seq[byte]): bool {.raises: [], gcsafe.} = false
proc passwordProvEmpty(username: seq[byte]): seq[byte] {.raises: [], gcsafe.} = @[]
proc passwordProvTest(username: seq[byte]): seq[byte] {.raises: [], gcsafe.} = @[1'u8, 2, 3, 4]

suite "Stun message encoding/decoding":
  test "Get BindingRequest + encode & decode with a set username":
    var
      udpConn = UdpConn.init(AnyAddress)
      conn = StunConn.init(
        udpConn,
        TransportAddress(AnyAddress),
        iceControlling=true,
        usernameProvider=usernameProvTest,
        usernameChecker=usernameCheckTrue,
        passwordProvider=passwordProvEmpty,
        newRng()
      )
      msg = conn.getBindingRequest()
      encoded = msg.encode(@[1'u8, 2, 3, 4])
      decoded = StunMessage.decode(encoded)
      messageIntegrity = decoded.attributes[^2]
      fingerprint = decoded.attributes[^1]

    decoded.attributes = decoded.attributes[0 ..< ^2]
    check:
      decoded == msg
      messageIntegrity.attributeType == AttrMessageIntegrity.uint16
      fingerprint.attributeType == AttrFingerprint.uint16
    conn.close()

  test "Get BindingResponse from BindingRequest + encode & decode":
    var
      udpConn = UdpConn.init(AnyAddress)
      conn = StunConn.init(
        udpConn,
        TransportAddress(AnyAddress),
        iceControlling=false,
        usernameProvider=usernameProvTest,
        usernameChecker=usernameCheckTrue,
        passwordProvider=passwordProvEmpty,
        newRng()
      )
      bindingRequest = conn.getBindingRequest()
      bindingResponse = conn.getBindingResponse(bindingRequest)
      encoded = bindingResponse.encode(@[1'u8, 2, 3, 4])
      decoded = StunMessage.decode(encoded)
      messageIntegrity = decoded.attributes[^2]
      fingerprint = decoded.attributes[^1]

    decoded.attributes = decoded.attributes[0 ..< ^2]
    check:
      bindingResponse == decoded
      messageIntegrity.attributeType == AttrMessageIntegrity.uint16
      fingerprint.attributeType == AttrFingerprint.uint16

suite "Stun checkForError":
  test "checkForError: Missing MessageIntegrity or Username":
    var
      udpConn = UdpConn.init(AnyAddress)
      conn = StunConn.init(
        udpConn,
        TransportAddress(AnyAddress),
        iceControlling=false,
        usernameProvider=usernameProvEmpty, # Use of an empty username provider
        usernameChecker=usernameCheckTrue,
        passwordProvider=passwordProvEmpty,
        newRng()
      )
      bindingRequest = conn.getBindingRequest()
      errorMissMessageIntegrity = conn.checkForError(bindingRequest).get()

    check:
      errorMissMessageIntegrity.getAttribute(ErrorCode).isSome()
      errorMissMessageIntegrity.getAttribute(ErrorCode).get().getErrorCode() == ECBadRequest

    let
      encoded = bindingRequest.encode(@[1'u8, 2, 3, 4]) # adds MessageIntegrity
      decoded = StunMessage.decode(encoded)
      errorMissUsername = conn.checkForError(decoded).get()

    check:
      errorMissUsername.getAttribute(ErrorCode).isSome()
      errorMissUsername.getAttribute(ErrorCode).get().getErrorCode() == ECBadRequest

  test "checkForError: UsernameChecker returns false":
    var
      udpConn = UdpConn.init(AnyAddress)
      conn = StunConn.init(
        udpConn,
        TransportAddress(AnyAddress),
        iceControlling=false,
        usernameProvider=usernameProvTest,
        usernameChecker=usernameCheckFalse, # Username provider returns false
        passwordProvider=passwordProvEmpty,
        newRng()
      )
      bindingRequest = conn.getBindingRequest()
      encoded = bindingRequest.encode(@[0'u8, 1, 2, 3])
      decoded = StunMessage.decode(encoded)
      error = conn.checkForError(decoded).get()

    check:
      error.getAttribute(ErrorCode).isSome()
      error.getAttribute(ErrorCode).get().getErrorCode() == ECUnauthorized
