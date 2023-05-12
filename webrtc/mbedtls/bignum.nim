#import strformat, os
#
## C include directory
#const root = currentSourcePath.parentDir
#const mbedtlsInclude = root/"mbedtls"/"include"
#const mbedtlsLibrary = root/"mbedtls"/"library"
#
#{.passc: fmt"-I{mbedtlsInclude} -I{mbedtlsLibrary}".}
#
import "md"
{.compile: "./mbedtls/library/bignum.c".}
{.compile: "./mbedtls/library/bignum_core.c".}
{.compile: "./mbedtls/library/constant_time.c".}
# Generated @ 2023-05-11T11:19:07+02:00
# Command line:
#   /home/lchenut/.nimble/pkgs/nimterop-0.6.13/nimterop/toast --pnim --preprocess --nocomment --noHeader --replace=_pms_rsa=u_pms_rsa --replace=_pms_dhm=u_pms_dhm --replace=_pms_ecdh=u_pms_ecdh --replace=_pms_psk=u_pms_psk --replace=_pms_dhe_psk=u_pms_dhe_psk --replace=_pms_rsa_psk=u_pms_rsa_psk --replace=_pms_ecdhe_psk=u_pms_ecdhe_psk --replace=_pms_ecjpake=u_pms_ecjpake --replace=private_xm1=private_xm1_1 --replace=private_xm2=private_xm2_1 --includeDirs=./mbedtls/include --includeDirs=./mbedtls/library ./mbedtls/include/mbedtls/bignum.h

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
defineEnum(mbedtls_mpi_gen_prime_flag_t)
const
  MBEDTLS_ERR_MPI_FILE_IO_ERROR* = -0x00000002
  MBEDTLS_ERR_MPI_BAD_INPUT_DATA* = -0x00000004
  MBEDTLS_ERR_MPI_INVALID_CHARACTER* = -0x00000006
  MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL* = -0x00000008
  MBEDTLS_ERR_MPI_NEGATIVE_VALUE* = -0x0000000A
  MBEDTLS_ERR_MPI_DIVISION_BY_ZERO* = -0x0000000C
  MBEDTLS_ERR_MPI_NOT_ACCEPTABLE* = -0x0000000E
  MBEDTLS_ERR_MPI_ALLOC_FAILED* = -0x00000010
  MBEDTLS_MPI_MAX_LIMBS* = 10000
  MBEDTLS_MPI_WINDOW_SIZE* = 2
  MBEDTLS_MPI_MAX_SIZE* = 1024
  MBEDTLS_MPI_MAX_BITS* = (8 * typeof(8)(MBEDTLS_MPI_MAX_SIZE))
  MBEDTLS_MPI_MAX_BITS_SCALE100* = (100 * typeof(100)(MBEDTLS_MPI_MAX_BITS))
  MBEDTLS_LN_2_DIV_LN_10_SCALE100* = 332
  MBEDTLS_MPI_RW_BUFFER_SIZE* = ((typeof(MBEDTLS_MPI_MAX_BITS_SCALE100)((MBEDTLS_MPI_MAX_BITS_SCALE100 +
      typeof(MBEDTLS_MPI_MAX_BITS_SCALE100)(MBEDTLS_LN_2_DIV_LN_10_SCALE100) -
      typeof(MBEDTLS_MPI_MAX_BITS_SCALE100)(1)) /
      typeof(MBEDTLS_MPI_MAX_BITS_SCALE100)(MBEDTLS_LN_2_DIV_LN_10_SCALE100))) +
      typeof(MBEDTLS_MPI_MAX_BITS_SCALE100)(10) +
      typeof(MBEDTLS_MPI_MAX_BITS_SCALE100)(6))
  MBEDTLS_MPI_GEN_PRIME_FLAG_DH* = (0x00000001).mbedtls_mpi_gen_prime_flag_t
  MBEDTLS_MPI_GEN_PRIME_FLAG_LOW_ERR* = (0x00000002).mbedtls_mpi_gen_prime_flag_t
type
  mbedtls_mpi_sint* = int64
  mbedtls_mpi_uint* = uint64
  mbedtls_t_udbl* = cuint
  mbedtls_mpi* {.bycopy.} = object
    private_s*: cint
    private_n*: uint
    private_p*: ptr mbedtls_mpi_uint

proc mbedtls_mpi_init*(X: ptr mbedtls_mpi) {.importc, cdecl.}
proc mbedtls_mpi_free*(X: ptr mbedtls_mpi) {.importc, cdecl.}
proc mbedtls_mpi_grow*(X: ptr mbedtls_mpi; nblimbs: uint): cint {.importc, cdecl.}
proc mbedtls_mpi_shrink*(X: ptr mbedtls_mpi; nblimbs: uint): cint {.importc,
    cdecl.}
proc mbedtls_mpi_copy*(X: ptr mbedtls_mpi; Y: ptr mbedtls_mpi): cint {.importc,
    cdecl.}
proc mbedtls_mpi_swap*(X: ptr mbedtls_mpi; Y: ptr mbedtls_mpi) {.importc, cdecl.}
proc mbedtls_mpi_safe_cond_assign*(X: ptr mbedtls_mpi; Y: ptr mbedtls_mpi;
                                   assign: byte): cint {.importc, cdecl.}
proc mbedtls_mpi_safe_cond_swap*(X: ptr mbedtls_mpi; Y: ptr mbedtls_mpi;
                                 swap: byte): cint {.importc, cdecl.}
proc mbedtls_mpi_lset*(X: ptr mbedtls_mpi; z: mbedtls_mpi_sint): cint {.importc,
    cdecl.}
proc mbedtls_mpi_get_bit*(X: ptr mbedtls_mpi; pos: uint): cint {.importc, cdecl.}
proc mbedtls_mpi_set_bit*(X: ptr mbedtls_mpi; pos: uint; val: byte): cint {.
    importc, cdecl.}
proc mbedtls_mpi_lsb*(X: ptr mbedtls_mpi): uint {.importc, cdecl.}
proc mbedtls_mpi_bitlen*(X: ptr mbedtls_mpi): uint {.importc, cdecl.}
proc mbedtls_mpi_size*(X: ptr mbedtls_mpi): uint {.importc, cdecl.}
proc mbedtls_mpi_read_string*(X: ptr mbedtls_mpi; radix: cint; s: cstring): cint {.
    importc, cdecl.}
proc mbedtls_mpi_write_string*(X: ptr mbedtls_mpi; radix: cint; buf: cstring;
                               buflen: uint; olen: ptr uint): cint {.importc,
    cdecl.}
proc mbedtls_mpi_read_file*(X: ptr mbedtls_mpi; radix: cint; fin: File): cint {.
    importc, cdecl.}
proc mbedtls_mpi_write_file*(p: cstring; X: ptr mbedtls_mpi; radix: cint;
                             fout: File): cint {.importc, cdecl.}
proc mbedtls_mpi_read_binary*(X: ptr mbedtls_mpi; buf: ptr byte; buflen: uint): cint {.
    importc, cdecl.}
proc mbedtls_mpi_read_binary_le*(X: ptr mbedtls_mpi; buf: ptr byte;
                                 buflen: uint): cint {.importc, cdecl.}
proc mbedtls_mpi_write_binary*(X: ptr mbedtls_mpi; buf: ptr byte; buflen: uint): cint {.
    importc, cdecl.}
proc mbedtls_mpi_write_binary_le*(X: ptr mbedtls_mpi; buf: ptr byte;
                                  buflen: uint): cint {.importc, cdecl.}
proc mbedtls_mpi_shift_l*(X: ptr mbedtls_mpi; count: uint): cint {.importc,
    cdecl.}
proc mbedtls_mpi_shift_r*(X: ptr mbedtls_mpi; count: uint): cint {.importc,
    cdecl.}
proc mbedtls_mpi_cmp_abs*(X: ptr mbedtls_mpi; Y: ptr mbedtls_mpi): cint {.
    importc, cdecl.}
proc mbedtls_mpi_cmp_mpi*(X: ptr mbedtls_mpi; Y: ptr mbedtls_mpi): cint {.
    importc, cdecl.}
proc mbedtls_mpi_lt_mpi_ct*(X: ptr mbedtls_mpi; Y: ptr mbedtls_mpi;
                            ret: ptr cuint): cint {.importc, cdecl.}
proc mbedtls_mpi_cmp_int*(X: ptr mbedtls_mpi; z: mbedtls_mpi_sint): cint {.
    importc, cdecl.}
proc mbedtls_mpi_add_abs*(X: ptr mbedtls_mpi; A: ptr mbedtls_mpi;
                          B: ptr mbedtls_mpi): cint {.importc, cdecl.}
proc mbedtls_mpi_sub_abs*(X: ptr mbedtls_mpi; A: ptr mbedtls_mpi;
                          B: ptr mbedtls_mpi): cint {.importc, cdecl.}
proc mbedtls_mpi_add_mpi*(X: ptr mbedtls_mpi; A: ptr mbedtls_mpi;
                          B: ptr mbedtls_mpi): cint {.importc, cdecl.}
proc mbedtls_mpi_sub_mpi*(X: ptr mbedtls_mpi; A: ptr mbedtls_mpi;
                          B: ptr mbedtls_mpi): cint {.importc, cdecl.}
proc mbedtls_mpi_add_int*(X: ptr mbedtls_mpi; A: ptr mbedtls_mpi;
                          b: mbedtls_mpi_sint): cint {.importc, cdecl.}
proc mbedtls_mpi_sub_int*(X: ptr mbedtls_mpi; A: ptr mbedtls_mpi;
                          b: mbedtls_mpi_sint): cint {.importc, cdecl.}
proc mbedtls_mpi_mul_mpi*(X: ptr mbedtls_mpi; A: ptr mbedtls_mpi;
                          B: ptr mbedtls_mpi): cint {.importc, cdecl.}
proc mbedtls_mpi_mul_int*(X: ptr mbedtls_mpi; A: ptr mbedtls_mpi;
                          b: mbedtls_mpi_uint): cint {.importc, cdecl.}
proc mbedtls_mpi_div_mpi*(Q: ptr mbedtls_mpi; R: ptr mbedtls_mpi;
                          A: ptr mbedtls_mpi; B: ptr mbedtls_mpi): cint {.
    importc, cdecl.}
proc mbedtls_mpi_div_int*(Q: ptr mbedtls_mpi; R: ptr mbedtls_mpi;
                          A: ptr mbedtls_mpi; b: mbedtls_mpi_sint): cint {.
    importc, cdecl.}
proc mbedtls_mpi_mod_mpi*(R: ptr mbedtls_mpi; A: ptr mbedtls_mpi;
                          B: ptr mbedtls_mpi): cint {.importc, cdecl.}
proc mbedtls_mpi_mod_int*(r: ptr mbedtls_mpi_uint; A: ptr mbedtls_mpi;
                          b: mbedtls_mpi_sint): cint {.importc, cdecl.}
proc mbedtls_mpi_exp_mod*(X: ptr mbedtls_mpi; A: ptr mbedtls_mpi;
                          E: ptr mbedtls_mpi; N: ptr mbedtls_mpi;
                          prec_RR: ptr mbedtls_mpi): cint {.importc, cdecl.}
proc mbedtls_mpi_fill_random*(X: ptr mbedtls_mpi; size: uint; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.
    importc, cdecl.}
proc mbedtls_mpi_random*(X: ptr mbedtls_mpi; min: mbedtls_mpi_sint;
                         N: ptr mbedtls_mpi; f_rng: proc (a1: pointer;
    a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.importc,
    cdecl.}
proc mbedtls_mpi_gcd*(G: ptr mbedtls_mpi; A: ptr mbedtls_mpi; B: ptr mbedtls_mpi): cint {.
    importc, cdecl.}
proc mbedtls_mpi_inv_mod*(X: ptr mbedtls_mpi; A: ptr mbedtls_mpi;
                          N: ptr mbedtls_mpi): cint {.importc, cdecl.}
proc mbedtls_mpi_is_prime_ext*(X: ptr mbedtls_mpi; rounds: cint; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.
    importc, cdecl.}
proc mbedtls_mpi_gen_prime*(X: ptr mbedtls_mpi; nbits: uint; flags: cint; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.
    importc, cdecl.}
proc mbedtls_mpi_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
