import chronos, stew/byteutils
import ../webrtc/sctp

proc main() {.async.} =
  let sctp = Sctp.new(port = 4242)
  sctp.startServer(13)
  let conn = await sctp.listen()
  let msg = await conn.read()
  echo "Receive: ", string.fromBytes(msg)
  await conn.close()
  sctp.stopServer()

waitFor(main())
