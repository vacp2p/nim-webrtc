import chronos, stew/byteutils
import ../webrtc/sctp

proc sendPong(conn: SctpConnection) {.async.} =
  var i = 0
  while true:
    let msg = await conn.read()
    echo "Received: ", string.fromBytes(msg)
    await conn.write(("pong " & $i).toBytes)
    i.inc()

proc main() {.async.} =
  let sctp = Sctp.new(port = 4242)
  sctp.startServer(13)
  while true:
    let conn = await sctp.listen()
    asyncSpawn conn.sendPong()

waitFor(main())
