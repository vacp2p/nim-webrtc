# Nim-WebRTC
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import std/times

import mbedtls/pk
import mbedtls/rsa
import mbedtls/ctr_drbg
import mbedtls/x509_crt
import mbedtls/bignum
import mbedtls/md

proc mbedtls_pk_rsa*(pk: mbedtls_pk_context): ptr mbedtls_rsa_context =
  var key = pk
  case mbedtls_pk_get_type(addr key):
    of MBEDTLS_PK_RSA:
      return cast[ptr mbedtls_rsa_context](pk.private_pk_ctx)
    else:
      return nil

template generateKey*(random: mbedtls_ctr_drbg_context): mbedtls_pk_context =
  var res: mbedtls_pk_context
  mb_pk_init(res)
  discard mbedtls_pk_setup(addr res, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))
  mb_rsa_gen_key(mb_pk_rsa(res), mbedtls_ctr_drbg_random, random, 4096, 65537)
  res

template generateCertificate*(random: mbedtls_ctr_drbg_context): mbedtls_x509_crt =
  let
    name = "C=FR,O=webrtc,CN=webrtc"
    time_format = initTimeFormat("YYYYMMddHHmmss")
    time_from = times.now().format(time_format)
    time_to = (times.now() + times.years(1)).format(time_format)

  var issuer_key = random.generateKey()
  var write_cert: mbedtls_x509write_cert
  var serial_mpi: mbedtls_mpi
  mb_x509write_crt_init(write_cert)
  mb_x509write_crt_set_md_alg(write_cert, MBEDTLS_MD_SHA256);
  mb_x509write_crt_set_subject_key(write_cert, issuer_key)
  mb_x509write_crt_set_issuer_key(write_cert, issuer_key)
  mb_x509write_crt_set_subject_name(write_cert, name)
  mb_x509write_crt_set_issuer_name(write_cert, name)
  mb_x509write_crt_set_validity(write_cert, time_from, time_to)
  mb_x509write_crt_set_basic_constraints(write_cert, 0, -1)
  mb_x509write_crt_set_subject_key_identifier(write_cert)
  mb_x509write_crt_set_authority_key_identifier(write_cert)
  mb_mpi_init(serial_mpi)
  let serial_hex = mb_mpi_read_string(serial_mpi, 16)
  mb_x509write_crt_set_serial(write_cert, serial_mpi)
  let buf = mb_x509write_crt_pem(write_cert, 4096, mbedtls_ctr_drbg_random, random)
  var res: mbedtls_x509_crt
  mb_x509_crt_parse(res, buf)
  res
