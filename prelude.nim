import strformat, os

# Socket definitions
import nativesockets

# C include directory
const root = currentSourcePath.parentDir
const usrsctpInclude = root/"usrsctp"/"usrsctplib"

{.passc: fmt"-I{usrsctpInclude}".}

