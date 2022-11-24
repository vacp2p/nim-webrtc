import chronos, stew/byteutils
import ../webrtc/sctp

proc main() {.async.} =
  let
    sctp = Sctp.new(port = 4244)
    address = TransportAddress(initTAddress("127.0.0.1:4242"))
    conn = await sctp.connect(address, sctpPort = 13)
  #let msg = await conn.read()
  #echo string.fromBytes(msg)
  await conn.write("toto".toBytes)
  await conn.close()

waitFor(main())
