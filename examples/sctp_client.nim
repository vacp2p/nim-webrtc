import chronos, stew/byteutils
import ../webrtc/sctp

proc main() {.async.} =
  let
    sctp = Sctp.new(port = 4244)
    address = TransportAddress(initTAddress("127.0.0.1:9899"))
    conn = await sctp.connect(address)
  await conn.write("toto".toBytes)
  await sleepAsync(3.seconds)

waitFor(main())
