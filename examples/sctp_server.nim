import chronos, stew/byteutils
import ../webrtc/sctp

proc main() {.async.} =
  let
    sctp = Sctp.new(isServer = true)
    address = initTAddress("127.0.0.1:9899")
    conn = await sctp.listen(address)
  let msg = await conn.read()
  echo string.fromBytes(msg)

waitFor(main())
