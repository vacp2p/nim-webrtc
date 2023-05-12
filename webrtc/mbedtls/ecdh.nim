#import strformat, os
#
## C include directory
#const root = currentSourcePath.parentDir
#const mbedtlsInclude = root/"mbedtls"/"include"
#const mbedtlsLibrary = root/"mbedtls"/"library"
#
#{.passc: fmt"-I{mbedtlsInclude} -I{mbedtlsLibrary}".}
#
import "private_access"
import "build_info"
import "mbedtls_config"
import "config_psa"
import "check_config"
import "ecp"
import "bignum"
{.compile: "./mbedtls/library/ecdh.c".}
# Generated @ 2023-05-11T11:19:09+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/ecdh.h

{.push hint[ConvFromXtoItselfNotNeeded]: off.}
import macros

macro defineEnum(typ: untyped): untyped =
  result = newNimNode(nnkStmtList)

  # Enum mapped to distinct cint
  result.add quote do:
    type `typ`* = distinct cint

  for i in ["+", "-", "*", "div", "mod", "shl", "shr", "or", "and", "xor", "<", "<=", "==", ">", ">="]:
    let
      ni = newIdentNode(i)
      typout = if i[0] in "<=>": newIdentNode("bool") else: typ # comparisons return bool
    if i[0] == '>': # cannot borrow `>` and `>=` from templates
      let
        nopp = if i.len == 2: newIdentNode("<=") else: newIdentNode("<")
      result.add quote do:
        proc `ni`*(x: `typ`, y: cint): `typout` = `nopp`(y, x)
        proc `ni`*(x: cint, y: `typ`): `typout` = `nopp`(y, x)
        proc `ni`*(x, y: `typ`): `typout` = `nopp`(y, x)
    else:
      result.add quote do:
        proc `ni`*(x: `typ`, y: cint): `typout` {.borrow.}
        proc `ni`*(x: cint, y: `typ`): `typout` {.borrow.}
        proc `ni`*(x, y: `typ`): `typout` {.borrow.}
    result.add quote do:
      proc `ni`*(x: `typ`, y: int): `typout` = `ni`(x, y.cint)
      proc `ni`*(x: int, y: `typ`): `typout` = `ni`(x.cint, y)

  let
    divop = newIdentNode("/")   # `/`()
    dlrop = newIdentNode("$")   # `$`()
    notop = newIdentNode("not") # `not`()
  result.add quote do:
    proc `divop`*(x, y: `typ`): `typ` = `typ`((x.float / y.float).cint)
    proc `divop`*(x: `typ`, y: cint): `typ` = `divop`(x, `typ`(y))
    proc `divop`*(x: cint, y: `typ`): `typ` = `divop`(`typ`(x), y)
    proc `divop`*(x: `typ`, y: int): `typ` = `divop`(x, y.cint)
    proc `divop`*(x: int, y: `typ`): `typ` = `divop`(x.cint, y)

    proc `dlrop`*(x: `typ`): string {.borrow.}
    proc `notop`*(x: `typ`): `typ` {.borrow.}


{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/include".}
{.passc: "-I./mbedtls/library".}
defineEnum(mbedtls_ecdh_side)
defineEnum(mbedtls_ecdh_variant)
const
  MBEDTLS_ECDH_OURS* = (0).mbedtls_ecdh_side
  MBEDTLS_ECDH_THEIRS* = (MBEDTLS_ECDH_OURS + 1).mbedtls_ecdh_side
  MBEDTLS_ECDH_VARIANT_NONE* = (0).mbedtls_ecdh_variant
  MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0* = (MBEDTLS_ECDH_VARIANT_NONE + 1).mbedtls_ecdh_variant
type
  mbedtls_ecdh_context_mbed* {.bycopy.} = object
    private_grp*: mbedtls_ecp_group
    private_d*: mbedtls_mpi
    private_Q*: mbedtls_ecp_point
    private_Qp*: mbedtls_ecp_point
    private_z*: mbedtls_mpi

  Union_ecdhh1* {.union, bycopy.} = object
    private_mbed_ecdh*: mbedtls_ecdh_context_mbed

  mbedtls_ecdh_context* {.bycopy.} = object
    private_point_format*: uint8
    private_grp_id*: mbedtls_ecp_group_id
    private_var*: mbedtls_ecdh_variant
    private_ctx*: Union_ecdhh1

proc mbedtls_ecdh_can_do*(gid: mbedtls_ecp_group_id): cint {.importc, cdecl.}
proc mbedtls_ecdh_gen_public*(grp: ptr mbedtls_ecp_group; d: ptr mbedtls_mpi;
                              Q: ptr mbedtls_ecp_point; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.
    importc, cdecl.}
proc mbedtls_ecdh_compute_shared*(grp: ptr mbedtls_ecp_group;
                                  z: ptr mbedtls_mpi; Q: ptr mbedtls_ecp_point;
                                  d: ptr mbedtls_mpi; f_rng: proc (a1: pointer;
    a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.importc,
    cdecl.}
proc mbedtls_ecdh_init*(ctx: ptr mbedtls_ecdh_context) {.importc, cdecl.}
proc mbedtls_ecdh_setup*(ctx: ptr mbedtls_ecdh_context;
                         grp_id: mbedtls_ecp_group_id): cint {.importc, cdecl.}
proc mbedtls_ecdh_free*(ctx: ptr mbedtls_ecdh_context) {.importc, cdecl.}
proc mbedtls_ecdh_make_params*(ctx: ptr mbedtls_ecdh_context; olen: ptr uint;
                               buf: ptr byte; blen: uint; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.
    importc, cdecl.}
proc mbedtls_ecdh_read_params*(ctx: ptr mbedtls_ecdh_context;
                               buf: ptr ptr byte; `end`: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_ecdh_get_params*(ctx: ptr mbedtls_ecdh_context;
                              key: ptr mbedtls_ecp_keypair;
                              side: mbedtls_ecdh_side): cint {.importc, cdecl.}
proc mbedtls_ecdh_make_public*(ctx: ptr mbedtls_ecdh_context; olen: ptr uint;
                               buf: ptr byte; blen: uint; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.
    importc, cdecl.}
proc mbedtls_ecdh_read_public*(ctx: ptr mbedtls_ecdh_context; buf: ptr byte;
                               blen: uint): cint {.importc, cdecl.}
proc mbedtls_ecdh_calc_secret*(ctx: ptr mbedtls_ecdh_context; olen: ptr uint;
                               buf: ptr byte; blen: uint; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.
    importc, cdecl.}
{.pop.}
