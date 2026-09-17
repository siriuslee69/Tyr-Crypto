## ---------------------------------------------------------------------
## | HQC Util <- moving bits between words and bytes, and wiping them   |
## ---------------------------------------------------------------------
##
## HQC stores long bit strings in 64-bit words but sends them as bytes.
## Both orders are "lowest first", so the conversion is a plain copy on
## a little-endian machine and an explicit shuffle everywhere else:
##
##   word 0 = 0x0807060504030201
##            |  |  |  |  |  |  |  '- byte 0 = 0x01
##            |  |  |  |  |  |  '---- byte 1 = 0x02
##            '------------------- byte 7 = 0x08
##
## Writing it out by hand rather than using `copyMem` costs almost
## nothing and keeps the result identical on any machine.

import std/volatile

import runePragmas
import ./params
import ./types

## Reference: [HQC-20250822] vector representation; wiping rules for `hqcWipeBytes`; pitfall: a plain loop can be optimised away, a volatile store cannot.
proc hqcWipeBytes*(A: var openArray[byte]) {.role: {helper}, raises: [].} =
  ## A: the buffer to erase.
  ## Overwrite secret bytes so the compiler is not allowed to skip the work.
  var
    i: int = 0
  while i < A.len:
    volatileStore(addr A[i], 0'u8)
    i = i + 1

## Reference: [HQC-20250822] vector representation; wiping rules for `hqcWipeWords`; pitfall: a plain loop can be optimised away, a volatile store cannot.
proc hqcWipeWords*(A: var openArray[uint64]) {.role: {helper}, raises: [].} =
  ## A: the word buffer to erase.
  ## Overwrite a secret bit string so the compiler cannot skip the work.
  var
    i: int = 0
  while i < A.len:
    volatileStore(addr A[i], 0'u64)
    i = i + 1

## Reference: [HQC-20250822] vector representation; wiping rules for `hqcWipeU16`; pitfall: a plain loop can be optimised away, a volatile store cannot.
proc hqcWipeU16*(A: var openArray[uint16]) {.role: {helper}, raises: [].} =
  ## A: the 16-bit buffer to erase.
  ## Overwrite Reed-Solomon scratch values that depend on the secret.
  var
    i: int = 0
  while i < A.len:
    volatileStore(addr A[i], 0'u16)
    i = i + 1

## Reference: [HQC-20250822] vector representation; allocation helper for `newHqcVec`; pitfall: every word above `n` bits must start at zero.
proc newHqcVec*(words: int): HqcVec {.role: {helper}, raises: [].} =
  ## words: how many 64-bit words the bit string needs.
  ## A fresh all-zero bit string.
  result = newSeq[uint64](words)

## Reference: [HQC-20250822] vector representation; word-to-byte packing for `hqcWordsToBytes`; pitfall: the order is lowest byte first, on every machine.
proc hqcWordsToBytes*(dst: var openArray[byte], V: openArray[uint64],
    count: int) {.role: {helper}, raises: [].} =
  ## dst/V/count: destination, source words, how many bytes to write.
  ## Unpack the first `count` bytes of a bit string, lowest byte first.
  var
    i: int = 0
  while i < count:
    dst[i] = byte((V[i shr 3] shr (8 * (i and 7))) and 0xff'u64)
    i = i + 1

## Reference: [HQC-20250822] vector representation; byte-to-word packing for `hqcBytesToWords`; pitfall: the destination must already be zeroed, because this only ORs bits in.
proc hqcBytesToWords*(V: var openArray[uint64], A: openArray[byte],
    o, count: int) {.role: {helper}, raises: [].} =
  ## V/A/o/count: destination words, source bytes, where to start, how many.
  ## Pack `count` bytes into a bit string, lowest byte first.
  var
    i: int = 0
  while i < count:
    V[i shr 3] = V[i shr 3] or (uint64(A[o + i]) shl (8 * (i and 7)))
    i = i + 1

## Reference: [HQC-20250822] vector representation; serialization helper for `hqcVecToByteSeq`; pitfall: the caller decides the length, not the word count.
proc hqcVecToByteSeq*(V: openArray[uint64], count: int): seq[byte]
    {.role: {helper}, raises: [].} =
  ## V/count: the bit string and how many bytes of it to keep.
  ## Copy a bit string out as a fresh byte sequence.
  result = newSeq[byte](count)
  hqcWordsToBytes(result, V, count)

## Reference: [HQC-20250822] Reed-Muller codeword layout; 32-bit lane read for `hqcGetU32`; pitfall: lane 2k lives in the low half of word k and lane 2k+1 in the high half.
proc hqcGetU32*(V: openArray[uint64], idx: int): uint32
    {.inline, role: {helper}, raises: [].} =
  ## V/idx: the bit string, and which 32-bit lane to read.
  ## Read one 32-bit lane out of a 64-bit-word bit string.
  result = uint32((V[idx shr 1] shr (32 * (idx and 1))) and 0xffffffff'u64)

## Reference: [HQC-20250822] Reed-Muller codeword layout; 32-bit lane write for `hqcSetU32`; pitfall: the other half of the word must survive untouched.
proc hqcSetU32*(V: var openArray[uint64], idx: int, x: uint32)
    {.inline, role: {helper}, raises: [].} =
  ## V/idx/x: the bit string, which 32-bit lane, and the value.
  ## Replace one 32-bit lane of a 64-bit-word bit string.
  var
    shift: int = 32 * (idx and 1)
  V[idx shr 1] = (V[idx shr 1] and not (0xffffffff'u64 shl shift)) or
    (uint64(x) shl shift)

## Reference: [HQC-20250822] vector arithmetic; bitwise addition for `hqcVecAdd`; pitfall: addition over GF(2) is exclusive-or, never a carrying add.
proc hqcVecAdd*(dst: var openArray[uint64], A, B: openArray[uint64],
    words: int) {.role: {math}, raises: [].} =
  ## dst/A/B/words: destination, the two inputs, how many words to combine.
  ## Add two bit strings. Over GF(2) that is exclusive-or, bit by bit.
  var
    i: int = 0
  while i < words:
    dst[i] = A[i] xor B[i]
    i = i + 1

## Reference: [HQC-20250822] vector truncation before the concatenated code; length clamping for `hqcVecTruncate`; pitfall: the partial last word must be masked before the tail words are cleared.
proc hqcVecTruncate*(V: var openArray[uint64], p: HqcParams)
    {.role: {sanitizer}, raises: [].} =
  ## V/p: the bit string to shorten, and the parameter set.
  ## Keep the lowest `n1n2` bits and force every higher bit to zero.
  var
    fullWords: int = p.n1n2 div 64
    restBits: int = p.n1n2 mod 64
    i: int = 0
  if restBits > 0:
    V[fullWords] = V[fullWords] and ((1'u64 shl restBits) - 1'u64)
    fullWords = fullWords + 1
  i = fullWords
  while i < p.vecNWords:
    V[i] = 0'u64
    i = i + 1

## Reference: [HQC-20250822] ciphertext comparison during decapsulation; constant-time equality for `hqcVecCompare`; pitfall: the answer must not depend on where the first difference is.
proc hqcVecCompare*(A, B: openArray[byte], count: int): byte
    {.role: {helper}, raises: [].} =
  ## A/B/count: the two byte strings and how many bytes to compare.
  ## Return 0 when the bytes are equal and 1 when they are not, always
  ## reading every byte so the timing says nothing about the contents.
  var
    r: uint16 = 0x0100'u16
    i: int = 0
  while i < count:
    r = r or uint16(A[i] xor B[i])
    i = i + 1
  result = byte((r - 1'u16) shr 8)

## Reference: [HQC-20250822] vector representation; wiping rules for `hqcWipeU32`; pitfall: a plain loop can be optimised away, a volatile store cannot.
proc hqcWipeU32*(A: var openArray[uint32]) {.role: {helper}, raises: [].} =
  ## A: the 32-bit buffer to erase.
  ## Overwrite the chosen bit positions, which are as secret as the key.
  var
    i: int = 0
  while i < A.len:
    volatileStore(addr A[i], 0'u32)
    i = i + 1
