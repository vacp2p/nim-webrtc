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

suite "Stun message encoding/decoding":
  test "Get BindingRequest + encode & decode with a set username":
    let
      udpConn = UdpConn.init(AnyAddress)
      conn = StunConn.init(
        udpConn,
        TransportAddress(AnyAddress),
        iceControlling=true,
        newRng()
      )
      msg = conn.getBindingRequest(username = "DoNotCreateMessageIntegrity")
      encoded = msg.encode(msg.getAttribute(AttrUsername))
      decoded = StunMessage.decode(encoded)

    check:
      msg.msgType == decoded.msgType and msg.msgType == StunBindingRequest
      msg.transactionId == decoded.transactionId
      msg.getAttribute(AttrUsername) == decoded.getAttribute(AttrUsername)
      decoded.getAttribute(AttrICEControlling).isSome()
      decoded.getAttribute(AttrICEControlled).isNone()
      # Priority for a public server.
      Priority.decode(msg.getAttribute(AttrPriority).get()).priority == 0x7effffff
      decoded.getAttribute(AttrFingerprint).isSome()
      msg.attributes.len() == decoded.attributes.len() - 1
    conn.close()

  test "Get BindingRequest + encode & decode with a libp2p valid random username":
    let
      udpConn = UdpConn.init(AnyAddress)
      conn = StunConn.init(
        udpConn,
        TransportAddress(AnyAddress),
        iceControlling=false,
        newRng()
      )
      msg = conn.getBindingRequest()
      encoded = msg.encode(msg.getAttribute(AttrUsername))
      decoded = StunMessage.decode(encoded)

    check:
      msg.msgType == decoded.msgType and msg.msgType == StunBindingRequest
      msg.transactionId == decoded.transactionId
      msg.getAttribute(AttrUsername) == decoded.getAttribute(AttrUsername)
      decoded.getAttribute(AttrICEControlling).isNone()
      decoded.getAttribute(AttrICEControlled).isSome()
      Priority.decode(msg.getAttribute(AttrPriority).get()).priority == 0x7effffff
      # encoding adds Fingerprint and Message-Integrity as attributes
      decoded.getAttribute(AttrMessageIntegrity).isSome()
      decoded.getAttribute(AttrFingerprint).isSome()
      msg.attributes.len() == decoded.attributes.len() - 2
    conn.close()

  test "Get BindingResponse from BindingRequest + encode & decode":
    let
      udpConn = UdpConn.init(AnyAddress)
      conn = StunConn.init(
        udpConn,
        TransportAddress(AnyAddress),
        iceControlling=false,
        newRng()
      )
      bindingRequest = conn.getBindingRequest()
      bindingResponse = conn.getBindingResponse(bindingRequest)
      encoded = bindingResponse.encode(bindingRequest.getAttribute(AttrUsername))
      decoded = StunMessage.decode(encoded)

    check:
      bindingResponse.msgType == StunBindingResponse
      decoded.msgType == StunBindingResponse
      decoded.transactionId == bindingRequest.transactionId
      decoded.getAttribute(AttrXORMappedAddress).isSome()
      decoded.getAttribute(AttrMessageIntegrity).isSome()
      decoded.getAttribute(AttrFingerprint).isSome()
      decoded.attributes.len() == 3

suite "Stun utilities":
  test "genUfrag":
    let s = genUfrag(newRng(), 2048)
    check s.len() == 2048
    for b in s:
      let c = b.chr()
      check isAlphaNumeric(c) or c == '+' or c == '/'
