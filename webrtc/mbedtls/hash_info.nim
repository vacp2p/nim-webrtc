# TODO: Put the .compile. pragma in one of the file using it without breaking everything
{.compile: "./mbedtls/library/hash_info.c".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
