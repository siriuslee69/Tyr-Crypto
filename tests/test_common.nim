import std/[unittest, strutils]
import ../src/protocols/common

suite "common helpers":
  test "raiseUnavailable provides descriptive error":
    const libName = "dummyLib"
    const flagName = "hasDummy"
    try:
      raiseUnavailable(libName, flagName)
      check false # should not reach
    except LibraryUnavailableError as ex:
      check ex.msg.contains(libName)
      check ex.msg.contains(flagName)

  test "raiseOperation raises CryptoOperationError":
    try:
      raiseOperation("dummy", "failed")
      check false
    except CryptoOperationError as ex:
      check ex.msg.contains("dummy")
      check ex.msg.contains("failed")
