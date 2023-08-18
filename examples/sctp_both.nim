import chronos, stew/byteutils
import ../webrtc/sctp as sc

let sctp = Sctp.new(port = 4242)
proc serv(fut: Future[void]) {.async.} =
  #let sctp = Sctp.new(port = 4242)
  sctp.startServer(13)
  fut.complete()
  let conn = await sctp.listen()
  echo "await read()"
  let msg = await conn.read()
  echo "read() finished"
  echo "Receive: ", string.fromBytes(msg)
  await conn.close()
  sctp.stopServer()

proc main() {.async.} =
  let fut = Future[void]()
  asyncSpawn serv(fut)
  await fut
  #let sctp = Sctp.new(port = 4244)
  let address = TransportAddress(initTAddress("127.0.0.1:4242"))
  let conn = await sctp.connect(address, sctpPort = 13)
  await conn.write("test".toBytes)
  await conn.close()

waitFor(main())
