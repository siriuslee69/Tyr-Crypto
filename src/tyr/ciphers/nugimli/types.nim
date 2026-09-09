## --------------------------------------------------------------------
## NuGimli Types <- fixed-width states and contiguous 128-bit chunk swaps
## --------------------------------------------------------------------

import runePragmas

const
  nugimliChunkWords* = 4
  nugimli512Bits* = 512
  nugimli1024Bits* = 1024
  nugimli2048Bits* = 2048
  nugimli512Rounds* = 24
  nugimli1024Rounds* = 28
  nugimli2048Rounds* = 32
  cascadeRoundDomain* = 0x43415343'u32

type
  NuGimli512* = array[nugimli512Bits div 32, uint32]
  NuGimli1024* = array[nugimli1024Bits div 32, uint32]
  NuGimli2048* = array[nugimli2048Bits div 32, uint32]

proc swapChunkBlocks*[N: static[int]](S: var array[N, uint32], a, b,
    c: int) {.role: {helper}.} =
  ## S: state whose contiguous 128-bit chunks are exchanged.
  ## a/b: first chunk index of each block. c: chunks in each block.
  var
    i: int = 0
  if a == b:
    return
  if c <= 0 or a < 0 or b < 0 or a + c > N div nugimliChunkWords or
      b + c > N div nugimliChunkWords:
    raise newException(ValueError, "NuGimli chunk swap is outside the state")
  if a < b + c and b < a + c:
    raise newException(ValueError, "NuGimli chunk swap blocks overlap")
  i = 0
  while i < c * nugimliChunkWords:
    swap(S[a * nugimliChunkWords + i], S[b * nugimliChunkWords + i])
    i = i + 1
