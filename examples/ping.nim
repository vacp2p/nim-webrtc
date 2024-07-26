import chronos, stew/byteutils
import ../webrtc/udp_transport
import ../webrtc/stun/stun_transport
import ../webrtc/dtls/dtls_transport
import ../webrtc/sctp/[sctp_transport, sctp_connection]

proc main() {.async.} =
  let laddr = initTAddress("127.0.0.1:4244")
  let udp = UdpTransport.new(laddr)
  let stun = Stun.new(udp)
  let dtls = Dtls.new(stun)
  let sctp = Sctp.new(dtls)

  let conn = await sctp.connect(initTAddress("127.0.0.1:4242"), sctpPort = 13)
  while true:
    await conn.write("ping".toBytes)
    let msg = await conn.read()
    echo "Received: ", string.fromBytes(msg.data)
    await sleepAsync(1.seconds)

waitFor(main())
