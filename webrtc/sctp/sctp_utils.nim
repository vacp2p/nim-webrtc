# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

template usrsctpAwait*(self: untyped, body: untyped): untyped =
  # usrsctpAwait is template which set `sentFuture` to nil then calls (usually)
  # an usrsctp function. If during the synchronous run of the usrsctp function
  # `sendCallback` is called, then `sentFuture` is set and waited.
  # self should be Sctp or SctpConn
  self.sentFuture = nil
  when type(body) is void:
    (body)
    if self.sentFuture != nil: await self.sentFuture
  else:
    let res = (body)
    if self.sentFuture != nil: await self.sentFuture
    res
