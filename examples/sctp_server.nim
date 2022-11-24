import chronos, stew/byteutils
import ../webrtc/sctp

proc main() {.async.} =
  let
    sctp = Sctp.new(port = 4242, isServer = true, sctpPort = 13)
    conn = await sctp.listen()
  #await conn.write("toto".toBytes)
  #await sleepAsync(3.seconds)
  let msg = await conn.read()
  echo "Receive: ", string.fromBytes(msg)
  await conn.close()

waitFor(main())
