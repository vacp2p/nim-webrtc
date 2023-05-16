{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}

const
  MBEDTLS_PSA_BUILTIN_ALG_HMAC* = 1
  PSA_WANT_ALG_HMAC* = 1
  PSA_WANT_KEY_TYPE_DERIVE* = 1
  PSA_WANT_KEY_TYPE_PASSWORD* = 1
  PSA_WANT_KEY_TYPE_PASSWORD_HASH* = 1
  PSA_WANT_KEY_TYPE_RAW_DATA* = 1
{.pop.}
