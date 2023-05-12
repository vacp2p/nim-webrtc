#import strformat, os
#
## C include directory
#const root = currentSourcePath.parentDir
#const mbedtlsInclude = root/"mbedtls"/"include"
#const mbedtlsLibrary = root/"mbedtls"/"library"
#
#{.passc: fmt"-I{mbedtlsInclude} -I{mbedtlsLibrary}".}
#
import "ecp"
import "bignum"
import "md"
import "hash_info"
import "platform_time"
{.compile: "./mbedtls/library/ecjpake.c".}
# Generated @ 2023-05-11T11:19:10+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/ecjpake.h

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
defineEnum(mbedtls_ecjpake_role)
const
  MBEDTLS_ECJPAKE_CLIENT* = (0).mbedtls_ecjpake_role
  MBEDTLS_ECJPAKE_SERVER* = (MBEDTLS_ECJPAKE_CLIENT + 1).mbedtls_ecjpake_role
type
  mbedtls_ecjpake_context* {.bycopy.} = object
    private_md_type*: mbedtls_md_type_t
    private_grp*: mbedtls_ecp_group
    private_role*: mbedtls_ecjpake_role
    private_point_format*: cint
    private_Xm1*: mbedtls_ecp_point
    private_Xm2*: mbedtls_ecp_point
    private_Xp1*: mbedtls_ecp_point
    private_Xp2*: mbedtls_ecp_point
    private_Xp*: mbedtls_ecp_point
    private_xm1_1*: mbedtls_mpi
    private_xm2_1*: mbedtls_mpi
    private_s*: mbedtls_mpi

proc mbedtls_ecjpake_init*(ctx: ptr mbedtls_ecjpake_context) {.importc, cdecl.}
proc mbedtls_ecjpake_setup*(ctx: ptr mbedtls_ecjpake_context;
                            role: mbedtls_ecjpake_role; hash: mbedtls_md_type_t;
                            curve: mbedtls_ecp_group_id; secret: ptr byte;
                            len: uint): cint {.importc, cdecl.}
proc mbedtls_ecjpake_set_point_format*(ctx: ptr mbedtls_ecjpake_context;
                                       point_format: cint): cint {.importc,
    cdecl.}
proc mbedtls_ecjpake_check*(ctx: ptr mbedtls_ecjpake_context): cint {.importc,
    cdecl.}
proc mbedtls_ecjpake_write_round_one*(ctx: ptr mbedtls_ecjpake_context;
                                      buf: ptr byte; len: uint;
                                      olen: ptr uint; f_rng: proc (a1: pointer;
    a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.importc,
    cdecl.}
proc mbedtls_ecjpake_read_round_one*(ctx: ptr mbedtls_ecjpake_context;
                                     buf: ptr byte; len: uint): cint {.
    importc, cdecl.}
proc mbedtls_ecjpake_write_round_two*(ctx: ptr mbedtls_ecjpake_context;
                                      buf: ptr byte; len: uint;
                                      olen: ptr uint; f_rng: proc (a1: pointer;
    a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.importc,
    cdecl.}
proc mbedtls_ecjpake_read_round_two*(ctx: ptr mbedtls_ecjpake_context;
                                     buf: ptr byte; len: uint): cint {.
    importc, cdecl.}
proc mbedtls_ecjpake_derive_secret*(ctx: ptr mbedtls_ecjpake_context;
                                    buf: ptr byte; len: uint; olen: ptr uint;
    f_rng: proc (a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.};
                                    p_rng: pointer): cint {.importc, cdecl.}
proc mbedtls_ecjpake_write_shared_key*(ctx: ptr mbedtls_ecjpake_context;
                                       buf: ptr byte; len: uint;
                                       olen: ptr uint; f_rng: proc (a1: pointer;
    a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.importc,
    cdecl.}
proc mbedtls_ecjpake_free*(ctx: ptr mbedtls_ecjpake_context) {.importc, cdecl.}
proc mbedtls_ecjpake_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
