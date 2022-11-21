import chronos, stew/byteutils
import ../webrtc/sctp

proc main() {.async.} =
  let
    sctp = Sctp.new(port = 4242, isServer = true, sctpPort = 13)
    conn = await sctp.listen()
  let msg = await conn.read()
  echo string.fromBytes(msg)

waitFor(main())
