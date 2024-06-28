when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

import chronos
import unittest2
export unittest2

const
  StreamTransportTrackerName = "stream.transport"
  StreamServerTrackerName = "stream.server"
  DgramTransportTrackerName = "datagram.transport"

  trackerNames = [
    StreamTransportTrackerName,
    StreamServerTrackerName,
    DgramTransportTrackerName,
  ]

template asyncTest*(name: string, body: untyped): untyped =
  test name:
    waitFor((proc () {.async, gcsafe.} = body)())

iterator testTrackers*(extras: openArray[string] = []): TrackerCounter =
  for name in trackerNames:
    let t = getTrackerCounter(name)
    yield t
  for name in extras:
    let t = getTrackerCounter(name)
    yield t

template checkTracker*(name: string) =
  var tracker = getTrackerCounter(name)
  if tracker.isCounterLeaked():
    checkpoint tracker.dump()
    fail()

template checkTrackers*() =
  for tracker in testTrackers():
    if tracker.isCounterLeaked():
      checkpoint tracker.dump()
      fail()
  # Also test the GC is not fooling with us
  try:
    GC_fullCollect()
  except:
    discard
