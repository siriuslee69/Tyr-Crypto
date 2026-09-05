## ---------------------------------------------------------------------
## | OQS Random Hook <- one fixed generator for every liboqs test       |
## ---------------------------------------------------------------------
##
## The library normally draws its own random bytes. A known-answer test
## needs the opposite: the very same bytes on every run, so that the
## pure-Nim result and the library result can be compared byte for byte.
## This module lends the library a generator that simply replays bytes
## the test hands over.
##
##   test feed  ->  [ b0 b1 b2 b3 ... bn ]
##                    ^
##                    +--- read position, moves forward on every request
##
## When the feed runs dry the generator hands back zeros and raises a
## flag. `oqsFeedRanShort()` reports that flag, so a test can tell a real
## match from one that only looks right because both sides were fed the
## same zeros.
##
## A second mode hands out a plain counting pattern - byte value
## `(base + position) mod 256`, endlessly. Speed measurements use it
## because it never runs dry and costs nothing to produce.
##
## Why the feed is not an ordinary sequence
## ----------------------------------------
## The library reaches back into Nim through a bare C function pointer.
## Nim only accepts such a pointer when the routine carries `gcsafe`, and
## a `gcsafe` routine may not read a global that the garbage collector
## owns - a growable sequence is exactly that. The feed therefore lives
## in memory this module asks for and gives back itself.
##
## Every routine here is for tests only. Nothing in `src/` uses it.

import metaPragmas
import ../src/tyr/bindings/liboqs

type
  OqsFeedMode = enum
    ## Which generator the library is currently borrowing.
    ##
    ##   ofmBytes    replay the handed-over bytes, then zeros
    ##   ofmCounter  endless (base + position) mod 256 pattern
    ofmBytes, ofmCounter

var
  oqsFeedData {.threadvar.}: ptr UncheckedArray[uint8]
  oqsFeedCap {.threadvar.}: int
  oqsFeedLen {.threadvar.}: int
  oqsFeedPos {.threadvar.}: int
  oqsFeedBase {.threadvar.}: int
  oqsFeedMode {.threadvar.}: OqsFeedMode
  oqsFeedShort {.threadvar.}: bool

proc reserveOqsFeed(n: int) {.role: {helper}.} =
  ## n: number of feed bytes that must fit.
  ## Grows the hand-managed feed buffer, never shrinks it.
  if n <= oqsFeedCap:
    return
  if oqsFeedData != nil:
    dealloc(oqsFeedData)
  oqsFeedData = cast[ptr UncheckedArray[uint8]](alloc0(n))
  oqsFeedCap = n

proc fillCounterBytes(D: ptr UncheckedArray[uint8], n: int) {.role: {helper}.} =
  ## D: destination the library asked to have filled.
  ## n: how many bytes it asked for.
  var
    i: int = 0
  while i < n:
    D[i] = uint8((oqsFeedBase + oqsFeedPos + i) and 0xff)
    i = i + 1
  oqsFeedPos = oqsFeedPos + n

proc fillFeedBytes(D: ptr UncheckedArray[uint8], n: int) {.role: {helper}.} =
  ## D: destination the library asked to have filled.
  ## n: how many bytes it asked for.
  ## Copies what is left of the feed, then pads with zeros and raises the
  ## short-read flag so the test can see the feed did not cover the call.
  var
    take: int = 0
    i: int = 0
  take = oqsFeedLen - oqsFeedPos
  if take < 0:
    take = 0
  if take > n:
    take = n
  while i < take:
    D[i] = oqsFeedData[oqsFeedPos + i]
    i = i + 1
  oqsFeedPos = oqsFeedPos + take
  if take == n:
    return
  oqsFeedShort = true
  while i < n:
    D[i] = 0'u8
    i = i + 1

proc oqsFeedCallback(random_array: ptr uint8,
    bytes_to_read: csize_t) {.cdecl, gcsafe, role: {dataFetcher}.} =
  ## random_array: buffer the library wants filled.
  ## bytes_to_read: its size in bytes.
  ## Called from C on the thread that entered the library.
  var
    D: ptr UncheckedArray[uint8] = cast[ptr UncheckedArray[uint8]](random_array)
    n: int = int(bytes_to_read)
  if random_array == nil or n <= 0:
    return
  if oqsFeedMode == ofmCounter:
    fillCounterBytes(D, n)
    return
  fillFeedBytes(D, n)

proc installOqsFeed*(F: openArray[byte]) {.role: {orchestrator}.} =
  ## F: exact bytes the library should receive, in order.
  ## Hands the library the replay generator. Pair with `restoreOqsRandom`.
  var
    i: int = 0
  reserveOqsFeed(max(F.len, 1))
  while i < F.len:
    oqsFeedData[i] = uint8(F[i])
    i = i + 1
  oqsFeedLen = F.len
  oqsFeedPos = 0
  oqsFeedMode = ofmBytes
  oqsFeedShort = false
  OQS_randombytes_custom_algorithm(oqsFeedCallback)

proc installOqsCounterFeed*(b: int) {.role: {orchestrator}.} =
  ## b: starting value of the counting pattern.
  ## Hands the library an endless pattern. Pair with `restoreOqsRandom`.
  oqsFeedLen = 0
  oqsFeedPos = 0
  oqsFeedBase = b
  oqsFeedMode = ofmCounter
  oqsFeedShort = false
  OQS_randombytes_custom_algorithm(oqsFeedCallback)

proc restoreOqsRandom*() {.role: {orchestrator}.} =
  ## Gives the library its own generator back and clears the feed.
  discard OQS_randombytes_switch_algorithm(oqsRandAlgSystem.cstring)
  oqsFeedLen = 0
  oqsFeedPos = 0
  oqsFeedMode = ofmBytes

proc oqsFeedRanShort*(): bool {.role: {parser}.} =
  ## True when the library asked for more bytes than the feed held.
  result = oqsFeedShort

proc withOqsFeed*(F: openArray[byte], body: proc ()) {.role: {orchestrator}.} =
  ## F: exact bytes the library should receive, in order.
  ## body: the work to run while the library uses them.
  installOqsFeed(F)
  try:
    body()
  finally:
    restoreOqsRandom()

proc withOqsCounterFeed*(b: int, body: proc ()) {.role: {orchestrator}.} =
  ## b: starting value of the counting pattern.
  ## body: the work to run while the library uses it.
  installOqsCounterFeed(b)
  try:
    body()
  finally:
    restoreOqsRandom()
