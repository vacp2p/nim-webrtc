import sequtils, bitops
import chronos, posix
import usrsctp
import stew/ranges/ptr_arith

const IPPROTO_SCTP = 132
let ta = initTAddress("127.0.0.1:4244")
let tar = initTAddress("127.0.0.1:4242")

proc discardFunc(transp: DatagramTransport, raddr: TransportAddress): Future[void] {.async.} = discard

proc connOutput(address: pointer,
                buffer: pointer,
                length: uint,
                tos: uint8,
                set_df: uint8): cint {.cdecl.} =
  echo "====> connOutput: ", usrsctp_dumppacket(buffer, length, SCTP_DUMP_OUTBOUND)
  let dg: ptr DatagramTransport = cast[ptr DatagramTransport](address)
  proc testSend() {.async.} =
    try:
      let buf = @(buffer.makeOpenArray(byte, int(length)))
      echo "START await sendTo START"
      await sendTo(dg[], tar, buf, int(length))
      echo "STOP  await sendTo  STOP"
    except CatchableError as exc:
      echo "Failure: ", exc.msg

  asyncSpawn testSend()
  echo "connOutput <===="

var connected = false
proc handleUpcall(sock: ptr socket, arg: pointer, length: cint) {.cdecl.} =
  let e = usrsctp_get_events(sock)
  echo "handleUpcall: event = ", e
  if bitor(e, SCTP_EVENT_WRITE) != 0 and not connected:
    echo "connect"
    connected = true
  elif bitor(e, SCTP_EVENT_READ) != 0:
    echo "recv"
  else:
    echo "/!\\ ERROR /!\\"

proc printf(format: cstring) {.cdecl, varargs.} = echo "printf"

proc handleEvents(dg: DatagramTransport, sock: ptr socket, sconn_addr: pointer) {.async.} =
  await sleepAsync(3.seconds)

proc main {.async, gcsafe.} =
  let fut = newFuture[void]()
  var p: pointer
  proc clientMark(transp: DatagramTransport, raddr: TransportAddress): Future[void] {.async.} =
    var msg = transp.getMessage()
    echo "Client Mark: ", usrsctp_dumppacket(addr msg[0], uint(msg.len), SCTP_DUMP_INBOUND)
    usrsctp_conninput(p, addr msg[0], uint(msg.len), 0)

  var dg = newDatagramTransport(clientMark, remote=tar, local=ta)
  p = cast[pointer](addr dg)
  usrsctp_init_nothreads(0, connOutput, printf)
  discard usrsctp_sysctl_set_sctp_ecn_enable(1)
  usrsctp_register_address(p)
  let sock = usrsctp_socket(AF_CONN, posix.SOCK_STREAM, IPPROTO_SCTP, nil, nil, 0, nil)
  var on: int = 1
  doAssert 0 == usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_RECVRCVINFO, addr on, sizeof(on).SockLen)
  doAssert 0 == usrsctp_set_non_blocking(sock, 1)
  doAssert 0 == usrsctp_set_upcall(sock, handleUpcall, nil)
  var sconn: Sockaddr_conn
  sconn.sconn_family = AF_CONN
  sconn.sconn_port = htons(0)
  sconn.sconn_addr = nil
  doAssert 0 == usrsctp_bind(sock, cast[ptr SockAddr](addr sconn), sizeof(sconn).SockLen)
  sconn.sconn_family = AF_CONN
  sconn.sconn_port = htons(13)
  sconn.sconn_addr = p
  let connErr = usrsctp_connect(sock, cast[ptr SockAddr](addr sconn), sizeof(sconn).SockLen)
  doAssert 0 == connErr or errno == EINPROGRESS, ($errno)

  await handleEvents(dg, sock, sconn.sconn_addr)

waitFor(main())
