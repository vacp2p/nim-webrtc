# Nim-WebRTC
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import tables, bitops, sequtils
import chronos
import usrsctp

type
  SctpConnection* = ref object
    udp: DatagramTransport
    address: TransportAddress

  SctpListener* = ref object
    udp: DatagramTransport
    connections: Table[TransportAddress, SctpConnection]

  Sctp* = ref object
    udps: seq[DatagramTransport]

proc new(T: typedesc[SctpConnection],
         udp: DatagramTransport,
         address: TransportAddress): T =
  T(udp: udp, address: address)

proc read(self: SctpConnection): Future[seq[byte]] = discard
proc write(self: SctpConnection, buf: seq[byte]) {.async.} = discard
proc close(self: SctpConnection) {.async.} = discard

proc getOrCreateConnection(self: SctpListener,
                           udp: DatagramTransport,
                           address: TransportAddress): SctpConnection =
  if self.connections.hasKey(address):
    return self.connections[address]
  let connection = SctpConnection.new(udp, address)
  self.connections[address] = connection
  return connection

proc new(T: typedesc[SctpListener], address: TransportAddress): T =
  let listener = T()
  proc onReceive(udp: DatagramTransport, address: TransportAddress) {.async.} =
    let connection = listener.getOrCreateConnection(udp, address)
    connection.receive(udp.getMessage())
  let udp = newDatagramTransport(onReceive, local = address)
  listener.udp = udp
  listener

proc new(T: typedesc[Sctp]): T =
  T()

proc listen(self: Sctp, address: TransportAddress): SctpListener =
  # what should happen when adding multiple time the same address
  proc onReceive(udp: DatagramTransport, address: TransportAddress) {.async.} =
    discard
  let udp = newDatagramTransport(onReceive, local = address)
  self.udps.add(udp)

proc connect(self: Sctp): Future[SctpConnection] = discard
proc dial(self: Sctp, address: TransportAddress): Future[SctpConnection] = discard
