import std/[os, strutils]
import ../src/tyr_crypto/wrapper/pin_key
import ../src/tyr_crypto/common
import ./helpers

when defined(hasLibsodium):
  proc promptLine(label: string): string =
    stdout.write(label)
    stdout.flushFile()
    result = stdin.readLine()

  proc bytesToString(data: openArray[uint8]): string =
    result = newString(data.len)
    for i, b in data:
      result[i] = char(b)

  proc zeroizeSeq(data: var seq[uint8]) =
    for i in 0 ..< data.len:
      data[i] = 0
    data.setLen(0)

  proc hexOrEmpty(data: openArray[uint8]): string =
    if data.len == 0:
      return "<empty>"
    toHex(data)

  proc echoKeyState(label: string, key: Key, masterKey: openArray[uint8]) =
    echo label
    echo "  masterKey: ", hexOrEmpty(masterKey)
    echo "  pinKdf: ", hexOrEmpty(key.pinKdf)
    echo "  encryptedMasterKey: ", hexOrEmpty(key.encryptedMasterKey)
    echo "  masterKeyNonce: ", hexOrEmpty(key.masterKeyNonce)
    echo "  pinSalt: ", hexOrEmpty(key.pinSalt)
    echo "  argon2Salt: ", hexOrEmpty(key.argon2Salt)
    echo "  argon2OpsLimit: ", key.argon2OpsLimit
    echo "  argon2MemLimit: ", key.argon2MemLimit

  proc writeCipher(path: string, cipher: EncryptedCiphertext) =
    let content = toHex(cipher.nonce) & "\n" &
      toHex(cipher.ciphertext) & "\n" &
      toHex(cipher.hmac) & "\n"
    writeFile(path, content)

  proc readCipher(path: string): EncryptedCiphertext =
    var lines: seq[string] = @[]
    for line in readFile(path).splitLines():
      let trimmed = line.strip()
      if trimmed.len > 0:
        lines.add(trimmed)
    if lines.len < 3:
      raise newException(ValueError, "ciphertext file is missing fields")
    result.nonce = hexToBytes(lines[0])
    result.ciphertext = hexToBytes(lines[1])
    result.hmac = hexToBytes(lines[2])

  when isMainModule:
    let password = promptLine("Password: ")
    let pin = promptLine("PIN: ")
    let text = promptLine("Text: ")

    var derived = deriveMasterKey(password)
    var key = derived.key
    var masterKey = derived.masterKey

    setPinKdf(key, pin)
    echoKeyState("Key state (unwrapped master key + pinKdf):", key, masterKey)

    let plaintext = toBytes(text)
    let cipher = encryptWithMasterKey(masterKey, plaintext)

    wrapMasterKeyWithPin(key, masterKey, pin)
    zeroizeSeq(masterKey)
    echoKeyState("Key state (wrapped, pinKdf cleared):", key, masterKey)

    let baseDir = splitFile(currentSourcePath()).dir
    let folder = joinPath(baseDir, "test_folder")
    createDir(folder)
    let path = joinPath(folder, "pin_cipher.txt")
    writeCipher(path, cipher)
    echo "Encrypted data written to: ", path

    let cipherRead = readCipher(path)
    while true:
      let pinAgain = promptLine("PIN to decrypt: ")
      try:
        var masterKey2 = unwrapMasterKeyWithPin(key, pinAgain)
        setPinKdf(key, pinAgain)
        echoKeyState("Key state (unwrapped again + pinKdf):", key, masterKey2)
        zeroizeSeq(key.pinKdf)
        let decrypted = decryptWithMasterKey(masterKey2, cipherRead)
        zeroizeSeq(masterKey2)

        echo "Decrypted text: ", bytesToString(decrypted)
        removeFile(path)
        break
      except CatchableError:
        echo "Authentication failed: incorrect PIN or corrupted data."
else:
  when isMainModule:
    raiseUnavailable("libsodium", "hasLibsodium")
