import os
import strformat

# Socket definitions
import nativesockets

when defined(windows):
  {.passl: "-lws2_32".}

# C include directories
const root = currentSourcePath.parentDir
const sourceInclude = root/"sources"/"lib"/"includes"
const buildInclude = root/"build"/"lib"/"includes"

{.passc: fmt"-I{sourceInclude} -I{buildInclude}".}
