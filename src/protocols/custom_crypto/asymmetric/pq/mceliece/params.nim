## Classic McEliece f-variants (6688128f / 6960119f / 8192128f) parameter table.
## Values mirror PQClean `params.h` but are exposed as a Nim record for reuse.

type
  McElieceVariant* = enum
    mceliece6688128f, mceliece6960119f, mceliece8192128f

  McElieceParams* = object
    name*: string           ## short human label, e.g. "mceliece6688128f"
    pqcleanName*: string    ## upstream PQClean / liboqs identifier
    gfBits*: int
    sysN*: int
    sysT*: int
    reductionTerms*: array[4, int]
    reductionTermCount*: int
    condBytes*: int
    irrBytes*: int
    pkNRows*: int
    pkNCols*: int
    pkRowBytes*: int
    syndBytes*: int
    gfMask*: uint16

const mcParamsTable*: array[McElieceVariant, McElieceParams] = [
  mceliece6688128f: McElieceParams(
    name: "mceliece6688128f",
    pqcleanName: "classic_mceliece_6688128f",
    gfBits: 13,
    sysN: 6688,
    sysT: 128,
    reductionTerms: [7, 2, 1, 0],
    reductionTermCount: 4,
    condBytes: ((1 shl (13 - 4)) * (2 * 13 - 1)),
    irrBytes: 128 * 2,
    pkNRows: 128 * 13,
    pkNCols: 6688 - (128 * 13),
    pkRowBytes: ((6688 - (128 * 13)) + 7) div 8,
    syndBytes: ((128 * 13) + 7) div 8,
    gfMask: (1'u16 shl 13) - 1'u16
  ),
  mceliece6960119f: McElieceParams(
    name: "mceliece6960119f",
    pqcleanName: "classic_mceliece_6960119f",
    gfBits: 13,
    sysN: 6960,
    sysT: 119,
    reductionTerms: [8, 0, 0, 0],
    reductionTermCount: 2,
    condBytes: ((1 shl (13 - 4)) * (2 * 13 - 1)),
    irrBytes: 119 * 2,
    pkNRows: 119 * 13,
    pkNCols: 6960 - (119 * 13),
    pkRowBytes: ((6960 - (119 * 13)) + 7) div 8,
    syndBytes: ((119 * 13) + 7) div 8,
    gfMask: (1'u16 shl 13) - 1'u16
  ),
  mceliece8192128f: McElieceParams(
    name: "mceliece8192128f",
    pqcleanName: "classic_mceliece_8192128f",
    gfBits: 13,
    sysN: 8192,
    sysT: 128,
    reductionTerms: [7, 2, 1, 0],
    reductionTermCount: 4,
    condBytes: ((1 shl (13 - 4)) * (2 * 13 - 1)),
    irrBytes: 128 * 2,
    pkNRows: 128 * 13,
    pkNCols: 8192 - (128 * 13),
    pkRowBytes: ((8192 - (128 * 13)) + 7) div 8,
    syndBytes: ((128 * 13) + 7) div 8,
    gfMask: (1'u16 shl 13) - 1'u16
  )
]

proc params*(v: McElieceVariant): McElieceParams {.inline.} =
  ## Return the fixed parameter set for the given Classic McEliece f-variant.
  mcParamsTable[v]
