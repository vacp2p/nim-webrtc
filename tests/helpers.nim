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

iterator testTrackers*(extras: openArray[string] = []): TrackerBase =
  for name in trackerNames:
    let t = getTracker(name)
    if not isNil(t): yield t
  for name in extras:
    let t = getTracker(name)
    if not isNil(t): yield t

template checkTracker*(name: string) =
  var tracker = getTracker(name)
  if tracker.isLeaked():
    checkpoint tracker.dump()
    fail()

template checkTrackers*() =
  for tracker in testTrackers():
    if tracker.isLeaked():
      checkpoint tracker.dump()
      fail()
  # Also test the GC is not fooling with us
  try:
    GC_fullCollect()
  except:
    discard
