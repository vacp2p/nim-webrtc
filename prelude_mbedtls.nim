import strformat, os

# Socket definitions
import nativesockets

# C include directory
const root = currentSourcePath.parentDir
const mbedtlsInclude = root/"mbedtls"/"include"
const mbedtlsLibrary = root/"mbedtls"/"library"

{.passc: fmt"-I{mbedtlsInclude}".}
{.passc: fmt"-I{mbedtlsLibrary}".}

