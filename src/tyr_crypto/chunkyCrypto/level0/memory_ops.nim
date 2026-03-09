## ============================================================
## | ChunkyCrypto Memory Ops <- RAM-aware chunk sizing         |
## ============================================================

import ./types

when defined(windows):
  import std/winlean

type
  MemInfo = object
    availBytes: int64

when defined(windows):
  type
    MemoryStatusEx {.pure.} = object
      dwLength: DWORD
      dwMemoryLoad: DWORD
      ullTotalPhys: uint64
      ullAvailPhys: uint64
      ullTotalPageFile: uint64
      ullAvailPageFile: uint64
      ullTotalVirtual: uint64
      ullAvailVirtual: uint64
      ullAvailExtendedVirtual: uint64

  proc GlobalMemoryStatusEx*(s: ptr MemoryStatusEx): WINBOOL
    {.importc: "GlobalMemoryStatusEx", stdcall, dynlib: "Kernel32.dll".}

proc readMemInfo(): MemInfo =
  var
    m: MemInfo
  when defined(windows):
    var s: MemoryStatusEx
    s.dwLength = DWORD(sizeof(MemoryStatusEx))
    if GlobalMemoryStatusEx(addr s) != 0:
      m.availBytes = int64(s.ullAvailPhys)
    else:
      m.availBytes = -1
  else:
    m.availBytes = -1
  result = m

proc availableRamBytes*(): int64 =
  let m = readMemInfo()
  result = m.availBytes

proc resolveChunkBytes*(o: ChunkyOptions): int64 =
  var
    v: int64
    a: int64
  v = o.chunkBytes
  if v <= 0:
    v = defaultChunkBytes
  if not o.forceChunkBytes:
    a = availableRamBytes()
    if a > 0 and a < lowRamThresholdBytes:
      v = fallbackChunkBytes
  result = v

proc resolveBufferBytes*(o: ChunkyOptions): int =
  var
    v: int
  v = o.bufferBytes
  if v <= 0:
    v = defaultBufferBytes
  if (v mod 64) != 0:
    v = v - (v mod 64)
    if v <= 0:
      v = 64
  result = v

proc resolveThreadCount*(o: ChunkyOptions, perThreadBytes: int64,
    chunkCount: int): int =
  var
    a: int64
    m: int64
    byMem: int
    byOpt: int
    t: int
  if chunkCount <= 0:
    return 0
  a = availableRamBytes()
  if a > 0 and perThreadBytes > 0:
    m = (a * 8) div 10
    byMem = int(m div perThreadBytes)
  else:
    byMem = 0
  if o.maxThreads > 0:
    byOpt = o.maxThreads
  else:
    byOpt = 0
  if byMem <= 0 and byOpt <= 0:
    t = chunkCount
  elif byMem <= 0:
    t = byOpt
  elif byOpt <= 0:
    t = byMem
  else:
    if byMem < byOpt:
      t = byMem
    else:
      t = byOpt
  if t < 1:
    t = 1
  if t > chunkCount:
    t = chunkCount
  result = t
