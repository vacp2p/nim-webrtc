import chronos, chronicles
import stun

logScope:
  topics = "webrtc"

let fut = newFuture[void]()
type
  WebRTC* = object
    udp: DatagramTransport

proc new*(T: typedesc[WebRTC], port: uint16 = 42657): T =
  logScope: topics = "webrtc"
  var webrtc = T()
  proc onReceive(udp: DatagramTransport, address: TransportAddress) {.async, gcsafe.} =
    let
      msg = udp.getMessage()
    if Stun.isMessage(msg):
      let res = Stun.getResponse(msg, address)
      echo res
      if res.isSome():
        await udp.sendTo(address, res.get().encode())

    trace "onReceive", isStun = Stun.isMessage(msg)
    if not fut.completed(): fut.complete()

  let
    laddr = initTAddress("127.0.0.1:" & $port)
    udp = newDatagramTransport(onReceive, local = laddr)
  trace "local address", laddr
  webrtc.udp = udp
  return webrtc
#
#proc main {.async.} =
#  echo "/ip4/127.0.0.1/udp/42657/webrtc/certhash/uEiDKBGpmOW3zQhiCHagHZ8igwfKNIp8rQCJWd5E5mIhGHw/p2p/12D3KooWFjMiMZLaCKEZRvMqKp5qUGduS6iBZ9RWQgYZXYtAAaPC"
#  discard WebRTC.new()
#  await fut
#  await sleepAsync(10.seconds)
#
#waitFor(main())
