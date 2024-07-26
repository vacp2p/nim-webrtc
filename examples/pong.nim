import chronos, stew/byteutils
import ../webrtc/udp_transport
import ../webrtc/stun/stun_transport
import ../webrtc/dtls/dtls_transport
import ../webrtc/sctp/[sctp_transport, sctp_connection]

proc sendPong(conn: SctpConn) {.async.} =
  var i = 0
  while true:
    let msg = await conn.read()
    echo "Received: ", string.fromBytes(msg.data)
    await conn.write(("pong " & $i).toBytes)
    i.inc()

proc main() {.async.} =
  let laddr = initTAddress("127.0.0.1:4242")
  let udp = UdpTransport.new(laddr)
  let stun = Stun.new(udp)
  let dtls = Dtls.new(stun)
  let sctp = Sctp.new(dtls)

  sctp.listen(13)
  while true:
    let conn = await sctp.accept()
    asyncSpawn conn.sendPong()

waitFor(main())
