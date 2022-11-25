import chronos, stew/byteutils
import ../webrtc/sctp

proc main() {.async.} =
  let sctp = Sctp.new(port = 4244)
  let conn = await sctp.connect(initTAddress("127.0.0.1:4242"), sctpPort = 13)
  while true:
    await conn.write("ping".toBytes)
    let msg = await conn.read()
    echo "Received: ", string.fromBytes(msg)
    await sleepAsync(1.seconds)

waitFor(main())
