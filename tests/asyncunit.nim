import unittest2, chronos
import chronos/unittest2/asynctests

export unittest2, chronos, asynctests

template asyncTeardown*(body: untyped): untyped =
  teardown:
    waitFor((
      proc() {.async, gcsafe.} =
        body
    )())

template asyncSetup*(body: untyped): untyped =
  setup:
    waitFor((
      proc() {.async, gcsafe.} =
        body
    )())

template flakyAsyncTest*(name: string, attempts: int, body: untyped): untyped =
  test name:
    var attemptNumber = 0
    while attemptNumber < attempts:
      let isLastAttempt = attemptNumber == attempts - 1
      inc attemptNumber
      try:
        waitFor((
          proc() {.async, gcsafe.} =
            body
        )())
      except Exception as e:
        if isLastAttempt: raise e
        else: testStatusIMPL = TestStatus.FAILED
      finally:
        if not isLastAttempt:
          if testStatusIMPL == TestStatus.FAILED:
            # Retry
            testStatusIMPL = TestStatus.OK
          else:
            break
