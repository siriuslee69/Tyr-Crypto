import std/bitops
import ./gimli_types

export gimli_types

when defined(amd64) or defined(i386) or defined(neon) or defined(arm64) or defined(aarch64):
  import ./gimli_sse
  export gimli_sse

proc gimliColumnRound(state: var Gimli_Block, column: int) {.inline.} =
  ## Single column transformation extracted (avoids nested for+let inside round).
  var
    x: uint32 = 0
    y: uint32 = 0
    z: uint32 = 0
  x = rotateLeftBits(state[column], 24)
  y = rotateLeftBits(state[4 + column], 9)
  z = state[8 + column]
  state[8 + column] = x xor (z shl 1) xor ((y and z) shl 2)
  state[4 + column] = y xor x xor ((x or z) shl 1)
  state[column] = z xor y xor ((x and y) shl 3)

proc gimli_core_ref*(state: var Gimli_Block) =
  ## Reference Gimli permutation (24 rounds).
  var
    round: uint32 = 24
    column: int = 0
  while round > 0'u32:
    column = 0
    while column < 4:
      gimliColumnRound(state, column)
      column = column + 1

    case (round and 3)
    of 0'u32:
      swap(state[0], state[1])
      swap(state[2], state[3])
      state[0] = state[0] xor (0x9e377900'u32 or round)
    of 2'u32:
      swap(state[0], state[2])
      swap(state[1], state[3])
    else:
      discard

    round.dec()

proc gimliPermute*(state: var Gimli_Block) {.inline.} =
  when defined(neon) or defined(arm64) or defined(aarch64):
    gimliPermuteNeon(state)
  elif defined(sse2):
    gimliPermuteSse(state)
  else:
    gimli_core_ref(state)
