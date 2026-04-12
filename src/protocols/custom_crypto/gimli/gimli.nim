import std/bitops
import ./gimli_types

export gimli_types

when defined(amd64) or defined(i386):
  import ./gimli_sse
  export gimli_sse

proc gimli_core_ref*(state: var Gimli_Block) =
  ## Reference Gimli permutation (24 rounds).
  var 
    round = 24'u32
  while round > 0'u32:
    for column in 0 .. 3:
      let x = rotateLeftBits(state[column], 24)
      let y = rotateLeftBits(state[4 + column], 9)
      let z = state[8 + column]
      state[8 + column] = x xor (z shl 1) xor ((y and z) shl 2)
      state[4 + column] = y xor x xor ((x or z) shl 1)
      state[column] = z xor y xor ((x and y) shl 3)

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
  gimli_core_ref(state)
