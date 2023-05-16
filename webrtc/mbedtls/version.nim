{.compile: "./mbedtls/library/version.c".}
{.compile: "./mbedtls/library/version_features.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}

proc mbedtls_version_get_number*(): cuint {.importc, cdecl.}
proc mbedtls_version_get_string*(string: cstring) {.importc, cdecl.}
proc mbedtls_version_get_string_full*(string: cstring) {.importc, cdecl.}
proc mbedtls_version_check_feature*(feature: cstring): cint {.importc, cdecl.}
{.pop.}
