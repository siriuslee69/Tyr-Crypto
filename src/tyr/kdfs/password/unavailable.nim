## -----------------------------------------------------------
## Password KDF without libsodium <- same names, each one refuses
## -----------------------------------------------------------
##
## Argon2id and the PIN key wrap come from libsodium. A build without
## `-d:hasLibsodium` still compiles code that calls them; every call
## raises LibraryUnavailableError naming the missing switch. There is no
## fast-hash fallback on purpose: a password needs a slow hash.

import ../../helpers/errors
import ../../aeads/types
import ./common
import runePragmas

template refuse() =
  raiseUnavailable("libsodium (Argon2id)", "hasLibsodium")

proc derivePasswordPinSecretFromBytesWithSalt*(ps, pins, ss: openArray[uint8],
    cs: string = kdfContextPasswordPin, ol: culonglong = 0'u64,
    ml: csize_t = 0, l: int = derivedSecretLenDefault): DerivedSecretBytes {.role: {orchestrator}.} =
  refuse()

proc derivePasswordPinSecretFromStringWithSalt*(p: string, pin: string,
    ss: openArray[uint8], cs: string = kdfContextPasswordPin,
    ol: culonglong = 0'u64, ml: csize_t = 0,
    l: int = derivedSecretLenDefault): DerivedSecretBytes {.role: {orchestrator}.} =
  refuse()

proc derivePatternBytesFromPasswordPinWithSalt*(p: string, pin: string,
    ss: openArray[uint8], l: int = 16): DerivedSecretBytes {.role: {orchestrator}.} =
  refuse()

proc withSecret*(key: var Key, op: SecretOp): seq[uint8] {.role: {orchestrator}.} =
  refuse()

proc deriveMasterKey*(password: string): tuple[key: Key, masterKey: seq[uint8]] {.role: {orchestrator}.} =
  refuse()

proc wrapMasterKeyWithPinBytes*(key: var Key, masterKey: openArray[uint8], pin: openArray[uint8]) {.role: {encryptor}.} =
  refuse()

proc wrapMasterKeyWithPin*(key: var Key, masterKey: openArray[uint8], pin: string) {.role: {encryptor}.} =
  refuse()

proc unwrapMasterKeyWithPinBytes*(key: var Key, pin: openArray[uint8]): seq[uint8] {.role: {decryptor}.} =
  refuse()

proc unwrapMasterKeyWithPin*(key: var Key, pin: string): seq[uint8] {.role: {decryptor}.} =
  refuse()

proc encryptWithMasterKey*(masterKey, plaintext: openArray[uint8]): EncryptedCiphertext {.role: {encryptor}.} =
  refuse()

proc decryptWithMasterKey*(masterKey: openArray[uint8], cipher: EncryptedCiphertext): seq[uint8] {.role: {decryptor}.} =
  refuse()

proc derivePinKdf*(pin: string, salt: openArray[uint8]): seq[uint8] {.role: {orchestrator}.} =
  refuse()

proc setPinKdfBytes*(key: var Key, pin: openArray[uint8]) {.role: {actor}.} =
  refuse()

proc setPinKdf*(key: var Key, pin: string) {.role: {actor}.} =
  refuse()

proc deriveKeyFromPassword*(password: string, pin: string): Key {.role: {orchestrator}.} =
  refuse()

proc encryptWithKey*(key: var Key, plaintext: seq[uint8]): EncryptedCiphertext {.role: {encryptor}.} =
  refuse()

proc deriveSymmetricKeysFromBytesWithSalt*(a: CipherSuite,
    ps, ss: openArray[uint8], ol: culonglong, ml: csize_t,
    ns: openArray[uint8], t: uint16): DerivedEncryptionKeys {.role: {orchestrator}.} =
  refuse()

proc deriveSymmetricKeysFromBytes*(a: CipherSuite,
    ps: openArray[uint8], ns: openArray[uint8], t: uint16): DerivedEncryptionKeys {.role: {orchestrator}.} =
  refuse()

proc deriveSymmetricKeysFromString*(a: CipherSuite,
    p: string, ns: openArray[uint8], t: uint16): DerivedEncryptionKeys {.role: {orchestrator}.} =
  refuse()

proc deriveHybridKexDuoSeedFromBytesWithSalt*(ps, ss: openArray[uint8],
    ol: culonglong, ml: csize_t): DerivedKexSeed {.role: {orchestrator}.} =
  refuse()

proc deriveHybridKexTripleSeedFromBytesWithSalt*(ps, ss: openArray[uint8],
    ol: culonglong, ml: csize_t): DerivedKexSeed {.role: {orchestrator}.} =
  refuse()

proc deriveHybridKexDuoSeedFromBytes*(ps: openArray[uint8]): DerivedKexSeed {.role: {orchestrator}.} =
  refuse()

proc deriveHybridKexTripleSeedFromBytes*(ps: openArray[uint8]): DerivedKexSeed {.role: {orchestrator}.} =
  refuse()

proc deriveHybridKexDuoSeedFromString*(p: string): DerivedKexSeed {.role: {orchestrator}.} =
  refuse()

proc deriveHybridKexTripleSeedFromString*(p: string): DerivedKexSeed {.role: {orchestrator}.} =
  refuse()
