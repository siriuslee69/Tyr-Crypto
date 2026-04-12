## Little-endian helpers and constant-time masks used across the Classic McEliece helpers.

type
  GF* = uint16

proc storeGF*(dest: var openArray[byte], a: GF) =
  ## Store a GF element to two bytes (little-endian).
  assert dest.len >= 2
  dest[0] = byte(a and 0xFF)
  dest[1] = byte((a shr 8) and 0xFF)

proc loadGF*(src: openArray[byte]): GF =
  ## Load a GF element from two bytes (little-endian) and mask to the field size.
  assert src.len >= 2
  let a = (uint16(src[1]) shl 8) or uint16(src[0])
  a and 0x1FFF'u16

proc load4*(src: openArray[byte]): uint32 =
  ## Load 4 bytes little-endian.
  assert src.len >= 4
  var ret = uint32(src[3])
  for i in countdown(2, 0):
    ret = (ret shl 8) or uint32(src[i])
  ret

proc store8*(dest: var openArray[byte], v: uint64) =
  ## Store 8 bytes little-endian.
  assert dest.len >= 8
  dest[0] = byte((v shr 0) and 0xFF)
  dest[1] = byte((v shr 8) and 0xFF)
  dest[2] = byte((v shr 16) and 0xFF)
  dest[3] = byte((v shr 24) and 0xFF)
  dest[4] = byte((v shr 32) and 0xFF)
  dest[5] = byte((v shr 40) and 0xFF)
  dest[6] = byte((v shr 48) and 0xFF)
  dest[7] = byte((v shr 56) and 0xFF)

proc load8*(src: openArray[byte]): uint64 =
  ## Load 8 bytes little-endian.
  assert src.len >= 8
  var ret = uint64(src[7])
  for i in countdown(6, 0):
    ret = (ret shl 8) or uint64(src[i])
  ret

proc bitrev*(a: GF): GF =
  ## Bit-reverse the 13-bit field element and drop the top 3 padding bits.
  var x = a
  x = ((x and 0x00FF'u16) shl 8) or ((x and 0xFF00'u16) shr 8)
  x = ((x and 0x0F0F'u16) shl 4) or ((x and 0xF0F0'u16) shr 4)
  x = ((x and 0x3333'u16) shl 2) or ((x and 0xCCCC'u16) shr 2)
  x = ((x and 0x5555'u16) shl 1) or ((x and 0xAAAA'u16) shr 1)
  (x shr 3) and 0x1FFF'u16

proc ctMaskNonZero*(x: GF): uint16 {.inline.} =
  ## Return 0xFFFF when x != 0, else 0x0000 (branch-free).
  var m = uint16(x)
  m = m - 1'u16
  m = m shr 15
  m = m - 1'u16
  m

proc ctMaskZero*(x: GF): uint16 {.inline.} =
  ## Return 0xFFFF when x == 0, else 0x0000 (branch-free).
  not ctMaskNonZero(x)
