# Nim-WebRTC
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import chronos

type
  WebRTCConn* = ref object of RootObj
    conn: WebRTCConn
    address: TransportAddress
    # isClosed: bool
    # isEof: bool

method init(self: WebRTCConn, conn: WebRTCConn, address: TransportAddress) {.async, base.} =
  self.conn = conn
  self.address = address

method close(self: WebRTCConn) {.async, base.} =
  doAssert(false, "not implemented!")

method write(self: WebRTCConn, msg: seq[byte]) {.async, base.} =
  doAssert(false, "not implemented!")

method read(self: WebRTCConn): seq[byte] =
  doAssert(false, "not implemented!")
