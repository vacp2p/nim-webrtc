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
import ../webrtc/stun/stun_connection
import ../webrtc/stun/stun_message
import ../webrtc/stun/stun_attributes
import ../webrtc/stun/stun_utils
import ./asyncunit

proc newRng(): ref HmacDrbgContext =
  HmacDrbgContext.new()

suite "Stun message encoding/decoding":
  test "Stun decoding":
    discard
  test "Stun encoding":
    discard
  test "getBindingResponse":
    discard
  test "Error while decoding":
    discard

suite "Stun utilities":
  test "genUfrag":
    let s = genUfrag(newRng(), 20)
    check s.len() == 20
    for c in s:
      check isAlphaNumeric(c.chr())
