# Nim-WebRTC
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import nativesockets
import chronos

var errno* {.importc, header: "<errno.h>".}: cint ## error variable

when defined(windows):
  import winlean
  const
    SctpAF_INET* = winlean.AF_INET
    SctpEINPROGRESS* = winlean.WSAEINPROGRESS.cint
else:
  const
    SctpAF_INET* = nativesockets.AF_INET
    SctpEINPROGRESS* = chronos.EINPROGRESS.cint

proc sctpStrerror*(): string =
  proc strerror(
    error: int
  ): cstring {.importc: "strerror", cdecl, header: "<string.h>".}
  return $(strerror(errno))
