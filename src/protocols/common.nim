type
  CryptoBindingError* = object of CatchableError
  LibraryUnavailableError* = object of CryptoBindingError
  CryptoOperationError* = object of CryptoBindingError

const
  buildHint* = "Enable the binding with the appropriate -d:has* flag and ensure the native library is available at link/load time."

proc raiseUnavailable*(libName, flagName: string) {.raises: [LibraryUnavailableError].} =
  ## Raises a descriptive error when a binding is accessed without the proper flag.
  raise newException(LibraryUnavailableError,
    libName & " bindings are disabled. Compile with -d:" & flagName & ". " & buildHint)

proc raiseOperation*(libName, details: string) {.raises: [CryptoOperationError].} =
  ## Utility to raise an operation error for native library failures.
  raise newException(CryptoOperationError, libName & ": " & details)

template checkStatus*(libName: string, ok: bool, details: string) =
  if not ok:
    raiseOperation(libName, details)
