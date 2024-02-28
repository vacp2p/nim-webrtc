packageName = "webrtc"
version = "0.0.1"
author = "Status Research & Development GmbH"
description = "Webrtc stack"
license = "MIT"
installDirs = @["usrsctp", "webrtc"]

requires "nim >= 1.2.0",
         "chronicles >= 0.10.2",
         "chronos >= 3.0.6",
         "https://github.com/status-im/nim-binary-serialization.git",
         "https://github.com/status-im/nim-mbedtls.git"

proc runTest(filename: string) =
  discard
