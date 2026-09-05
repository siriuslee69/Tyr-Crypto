## ---------------------------------------------------------------------
## | KEM Material <- typed key-exchange material, sizes in the type     |
## ---------------------------------------------------------------------
##
##   var kp  = genKeypair(kyber0TyrSendM)
##   var c   = seal(kyber0TyrSendM(receiverPublicKey: kp.publicKey))
##   var key = open(c.envelope, kyber0TyrOpenM(receiverSecretKey: kp.secretKey))
##
## `seal` and `open` name the two halves of a key exchange. Sealing
## produces two things and they must not be confused:
##
##   AsymEnvelope    the public part. Safe to send or store.
##   sharedSecret    the local part. NEVER send this; it IS the key.
##
## `AsymCipher` holds both, which is why `seal` returns it and only
## `.envelope` goes on the wire. Sending an `AsymCipher` whole would ship
## the secret alongside the ciphertext meant to protect it.
##
## Send material and open material are separate types, and only the open
## side holds a secret key - the same guard the signature material uses.
##
## Two routes per family
## ---------------------
##   kyber0SendM      the library-backed route (liboqs)
##   kyber0TyrSendM   Tyr's own pure-Nim implementation
##
## Composing several at once
## -------------------------
## The generic `seal(a, b)` / `open(envs, a, b)` helpers at the bottom run
## two or three independent exchanges together, which is how a hybrid is
## built: one post-quantum KEM plus X25519, so breaking either alone is
## not enough.

import std/[atomics, locks, monotimes, os, times]

import ../helpers/errors
import ../helpers/material
import ../helpers/tiers
import ../helpers/random
import ../helpers/secure_memory
import ../hashes/sha3
import ../bindings/liboqs
import ./x25519 as customX25519
import ./bike as customBike
import ./frodo as customFrodo
import ./kyber as customKyber
import ./mceliece as customMcEliece

export material

const
  x25519KeyBytes = 32

type
  ## Material for sending an X25519-derived shared secret.
  x25519SendM* = object
    receiverPublicKey*: array[32, byte]
  ## Material for opening an X25519-derived shared secret.
  x25519OpenM* = object
    receiverSecretKey*: array[32, byte]
  ## Material for Kyber tier-0 encapsulation.
  kyber0SendM* = object
    receiverPublicKey*: array[1184, byte]
  ## Material for Kyber tier-0 decapsulation.
  kyber0OpenM* = object
    receiverSecretKey*: array[2400, byte]
  ## Material for Kyber tier-1 encapsulation.
  kyber1SendM* = object
    receiverPublicKey*: array[1568, byte]
  ## Material for Kyber tier-1 decapsulation.
  kyber1OpenM* = object
    receiverSecretKey*: array[3168, byte]
  ## Material for the pure-Nim Tyr Kyber tier-0 encapsulation path.
  kyber0TyrSendM* = object
    receiverPublicKey*: array[1184, byte]
  ## Material for the pure-Nim Tyr Kyber tier-0 decapsulation path.
  kyber0TyrOpenM* = object
    receiverSecretKey*: array[2400, byte]
  ## Material for the pure-Nim Tyr Kyber tier-1 encapsulation path.
  kyber1TyrSendM* = object
    receiverPublicKey*: array[1568, byte]
  ## Material for the pure-Nim Tyr Kyber tier-1 decapsulation path.
  kyber1TyrOpenM* = object
    receiverSecretKey*: array[3168, byte]
  ## Material for McEliece tier-0 encapsulation.
  mceliece0SendM* = object
    receiverPublicKey*: array[1044992, byte]
  ## Material for McEliece tier-0 decapsulation.
  mceliece0OpenM* = object
    receiverSecretKey*: array[13932, byte]
  ## Material for McEliece tier-1 encapsulation.
  mceliece1SendM* = object
    receiverPublicKey*: array[1047319, byte]
  ## Material for McEliece tier-1 decapsulation.
  mceliece1OpenM* = object
    receiverSecretKey*: array[13948, byte]
  ## Material for McEliece tier-2 encapsulation.
  mceliece2SendM* = object
    receiverPublicKey*: array[1357824, byte]
  ## Material for McEliece tier-2 decapsulation.
  mceliece2OpenM* = object
    receiverSecretKey*: array[14120, byte]
  ## Material for the pure-Nim Tyr McEliece tier-0 encapsulation path.
  mceliece0TyrSendM* = object
    receiverPublicKey*: array[1044992, byte]
  ## Material for the pure-Nim Tyr McEliece tier-0 decapsulation path.
  mceliece0TyrOpenM* = object
    receiverSecretKey*: array[13932, byte]
  ## Material for the pure-Nim Tyr McEliece tier-1 encapsulation path.
  mceliece1TyrSendM* = object
    receiverPublicKey*: array[1047319, byte]
  ## Material for the pure-Nim Tyr McEliece tier-1 decapsulation path.
  mceliece1TyrOpenM* = object
    receiverSecretKey*: array[13948, byte]
  ## Material for the pure-Nim Tyr McEliece tier-2 encapsulation path.
  mceliece2TyrSendM* = object
    receiverPublicKey*: array[1357824, byte]
  ## Material for the pure-Nim Tyr McEliece tier-2 decapsulation path.
  mceliece2TyrOpenM* = object
    receiverSecretKey*: array[14120, byte]
  ## Material for Frodo tier-0 AES encapsulation.
  frodo0AesSendM* = object
    receiverPublicKey*: array[9616, byte]
  ## Material for Frodo tier-0 AES decapsulation.
  frodo0AesOpenM* = object
    receiverSecretKey*: array[19888, byte]
  ## Material for Frodo tier-0 SHAKE encapsulation.
  frodo0ShakeSendM* = object
    receiverPublicKey*: array[9616, byte]
  ## Material for Frodo tier-0 SHAKE decapsulation.
  frodo0ShakeOpenM* = object
    receiverSecretKey*: array[19888, byte]
  ## Material for Frodo tier-1 AES encapsulation.
  frodo1AesSendM* = object
    receiverPublicKey*: array[15632, byte]
  ## Material for Frodo tier-1 AES decapsulation.
  frodo1AesOpenM* = object
    receiverSecretKey*: array[31296, byte]
  ## Material for Frodo tier-1 SHAKE encapsulation.
  frodo1ShakeSendM* = object
    receiverPublicKey*: array[15632, byte]
  ## Material for Frodo tier-1 SHAKE decapsulation.
  frodo1ShakeOpenM* = object
    receiverSecretKey*: array[31296, byte]
  ## Material for Frodo tier-2 AES encapsulation.
  frodo2AesSendM* = object
    receiverPublicKey*: array[21520, byte]
  ## Material for Frodo tier-2 AES decapsulation.
  frodo2AesOpenM* = object
    receiverSecretKey*: array[43088, byte]
  ## Material for Frodo tier-2 SHAKE encapsulation.
  frodo2ShakeSendM* = object
    receiverPublicKey*: array[21520, byte]
  ## Material for Frodo tier-2 SHAKE decapsulation.
  frodo2ShakeOpenM* = object
    receiverSecretKey*: array[43088, byte]
  ## Material for the pure-Nim Tyr Frodo tier-0 AES encapsulation path.
  frodo0AesTyrSendM* = object
    receiverPublicKey*: array[9616, byte]
  ## Material for the pure-Nim Tyr Frodo tier-0 AES decapsulation path.
  frodo0AesTyrOpenM* = object
    receiverSecretKey*: array[19888, byte]
  ## Material for the pure-Nim Tyr Frodo tier-0 SHAKE encapsulation path.
  frodo0ShakeTyrSendM* = object
    receiverPublicKey*: array[9616, byte]
  ## Material for the pure-Nim Tyr Frodo tier-0 SHAKE decapsulation path.
  frodo0ShakeTyrOpenM* = object
    receiverSecretKey*: array[19888, byte]
  ## Material for the pure-Nim Tyr Frodo tier-1 AES encapsulation path.
  frodo1AesTyrSendM* = object
    receiverPublicKey*: array[15632, byte]
  ## Material for the pure-Nim Tyr Frodo tier-1 AES decapsulation path.
  frodo1AesTyrOpenM* = object
    receiverSecretKey*: array[31296, byte]
  ## Material for the pure-Nim Tyr Frodo tier-1 SHAKE encapsulation path.
  frodo1ShakeTyrSendM* = object
    receiverPublicKey*: array[15632, byte]
  ## Material for the pure-Nim Tyr Frodo tier-1 SHAKE decapsulation path.
  frodo1ShakeTyrOpenM* = object
    receiverSecretKey*: array[31296, byte]
  ## Material for the pure-Nim Tyr Frodo tier-2 AES encapsulation path.
  frodo2AesTyrSendM* = object
    receiverPublicKey*: array[21520, byte]
  ## Material for the pure-Nim Tyr Frodo tier-2 AES decapsulation path.
  frodo2AesTyrOpenM* = object
    receiverSecretKey*: array[43088, byte]
  ## Material for the pure-Nim Tyr Frodo tier-2 SHAKE encapsulation path.
  frodo2ShakeTyrSendM* = object
    receiverPublicKey*: array[21520, byte]
  ## Material for the pure-Nim Tyr Frodo tier-2 SHAKE decapsulation path.
  frodo2ShakeTyrOpenM* = object
    receiverSecretKey*: array[43088, byte]
  ## Material for NTRU Prime tier-0 encapsulation.
  ntruprime0SendM* = object
    ## ntruprime0 is currently bound to sntrup761 in the checked-out liboqs tree.
    receiverPublicKey*: array[1158, byte]
  ## Material for NTRU Prime tier-0 decapsulation.
  ntruprime0OpenM* = object
    receiverSecretKey*: array[1763, byte]
  ## Material for BIKE tier-0 encapsulation.
  bike0SendM* = object
    ## bike0 is currently bound to BIKE-L1 in the checked-out liboqs tree.
    receiverPublicKey*: array[1541, byte]
  ## Material for BIKE tier-0 decapsulation.
  bike0OpenM* = object
    receiverSecretKey*: array[5223, byte]
  ## Material for the pure-Nim Tyr BIKE tier-0 encapsulation path.
  bike0TyrSendM* = object
    receiverPublicKey*: array[1541, byte]
  ## Material for the pure-Nim Tyr BIKE tier-0 decapsulation path.
  bike0TyrOpenM* = object
    receiverSecretKey*: array[5223, byte]

## ╭⟢ Which layout entry each material type names

proc algorithmOf*(T: typedesc[x25519SendM]): AlgorithmKind = akX25519Send
proc algorithmOf*(T: typedesc[x25519OpenM]): AlgorithmKind = akX25519Open
proc algorithmOf*(T: typedesc[kyber0SendM]): AlgorithmKind = akKyber0Send
proc algorithmOf*(T: typedesc[kyber0OpenM]): AlgorithmKind = akKyber0Open
proc algorithmOf*(T: typedesc[kyber1SendM]): AlgorithmKind = akKyber1Send
proc algorithmOf*(T: typedesc[kyber1OpenM]): AlgorithmKind = akKyber1Open
proc algorithmOf*(T: typedesc[kyber0TyrSendM]): AlgorithmKind = akKyber0TyrSend
proc algorithmOf*(T: typedesc[kyber0TyrOpenM]): AlgorithmKind = akKyber0TyrOpen
proc algorithmOf*(T: typedesc[kyber1TyrSendM]): AlgorithmKind = akKyber1TyrSend
proc algorithmOf*(T: typedesc[kyber1TyrOpenM]): AlgorithmKind = akKyber1TyrOpen
proc algorithmOf*(T: typedesc[mceliece0SendM]): AlgorithmKind = akMcEliece0Send
proc algorithmOf*(T: typedesc[mceliece0OpenM]): AlgorithmKind = akMcEliece0Open
proc algorithmOf*(T: typedesc[mceliece1SendM]): AlgorithmKind = akMcEliece1Send
proc algorithmOf*(T: typedesc[mceliece1OpenM]): AlgorithmKind = akMcEliece1Open
proc algorithmOf*(T: typedesc[mceliece2SendM]): AlgorithmKind = akMcEliece2Send
proc algorithmOf*(T: typedesc[mceliece2OpenM]): AlgorithmKind = akMcEliece2Open
proc algorithmOf*(T: typedesc[mceliece0TyrSendM]): AlgorithmKind = akMcEliece0TyrSend
proc algorithmOf*(T: typedesc[mceliece0TyrOpenM]): AlgorithmKind = akMcEliece0TyrOpen
proc algorithmOf*(T: typedesc[mceliece1TyrSendM]): AlgorithmKind = akMcEliece1TyrSend
proc algorithmOf*(T: typedesc[mceliece1TyrOpenM]): AlgorithmKind = akMcEliece1TyrOpen
proc algorithmOf*(T: typedesc[mceliece2TyrSendM]): AlgorithmKind = akMcEliece2TyrSend
proc algorithmOf*(T: typedesc[mceliece2TyrOpenM]): AlgorithmKind = akMcEliece2TyrOpen
proc algorithmOf*(T: typedesc[frodo0AesSendM]): AlgorithmKind = akFrodo0AesSend
proc algorithmOf*(T: typedesc[frodo0AesOpenM]): AlgorithmKind = akFrodo0AesOpen
proc algorithmOf*(T: typedesc[frodo0ShakeSendM]): AlgorithmKind = akFrodo0ShakeSend
proc algorithmOf*(T: typedesc[frodo0ShakeOpenM]): AlgorithmKind = akFrodo0ShakeOpen
proc algorithmOf*(T: typedesc[frodo1AesSendM]): AlgorithmKind = akFrodo1AesSend
proc algorithmOf*(T: typedesc[frodo1AesOpenM]): AlgorithmKind = akFrodo1AesOpen
proc algorithmOf*(T: typedesc[frodo1ShakeSendM]): AlgorithmKind = akFrodo1ShakeSend
proc algorithmOf*(T: typedesc[frodo1ShakeOpenM]): AlgorithmKind = akFrodo1ShakeOpen
proc algorithmOf*(T: typedesc[frodo2AesSendM]): AlgorithmKind = akFrodo2AesSend
proc algorithmOf*(T: typedesc[frodo2AesOpenM]): AlgorithmKind = akFrodo2AesOpen
proc algorithmOf*(T: typedesc[frodo2ShakeSendM]): AlgorithmKind = akFrodo2ShakeSend
proc algorithmOf*(T: typedesc[frodo2ShakeOpenM]): AlgorithmKind = akFrodo2ShakeOpen
proc algorithmOf*(T: typedesc[frodo0AesTyrSendM]): AlgorithmKind = akFrodo0AesTyrSend
proc algorithmOf*(T: typedesc[frodo0AesTyrOpenM]): AlgorithmKind = akFrodo0AesTyrOpen
proc algorithmOf*(T: typedesc[frodo0ShakeTyrSendM]): AlgorithmKind = akFrodo0ShakeTyrSend
proc algorithmOf*(T: typedesc[frodo0ShakeTyrOpenM]): AlgorithmKind = akFrodo0ShakeTyrOpen
proc algorithmOf*(T: typedesc[frodo1AesTyrSendM]): AlgorithmKind = akFrodo1AesTyrSend
proc algorithmOf*(T: typedesc[frodo1AesTyrOpenM]): AlgorithmKind = akFrodo1AesTyrOpen
proc algorithmOf*(T: typedesc[frodo1ShakeTyrSendM]): AlgorithmKind = akFrodo1ShakeTyrSend
proc algorithmOf*(T: typedesc[frodo1ShakeTyrOpenM]): AlgorithmKind = akFrodo1ShakeTyrOpen
proc algorithmOf*(T: typedesc[frodo2AesTyrSendM]): AlgorithmKind = akFrodo2AesTyrSend
proc algorithmOf*(T: typedesc[frodo2AesTyrOpenM]): AlgorithmKind = akFrodo2AesTyrOpen
proc algorithmOf*(T: typedesc[frodo2ShakeTyrSendM]): AlgorithmKind = akFrodo2ShakeTyrSend
proc algorithmOf*(T: typedesc[frodo2ShakeTyrOpenM]): AlgorithmKind = akFrodo2ShakeTyrOpen
proc algorithmOf*(T: typedesc[ntruprime0SendM]): AlgorithmKind = akNtruPrime0Send
proc algorithmOf*(T: typedesc[ntruprime0OpenM]): AlgorithmKind = akNtruPrime0Open
proc algorithmOf*(T: typedesc[bike0TyrSendM]): AlgorithmKind = akBike0TyrSend
proc algorithmOf*(T: typedesc[bike0TyrOpenM]): AlgorithmKind = akBike0TyrOpen
proc algorithmOf*(T: typedesc[bike0SendM]): AlgorithmKind = akBike0Send
proc algorithmOf*(T: typedesc[bike0OpenM]): AlgorithmKind = akBike0Open

## ╭⟢ Entropy for the library backend
##
## liboqs draws its own randomness. These let Tyr mix extra entropy in
## for one call and put the default generator back afterwards, under a
## lock so two threads cannot interleave the swap.
##
## The C library reaches back into Nim through a plain function pointer.
## Nim only accepts such a function pointer when the routine is marked
## `gcsafe`, and a `gcsafe` routine may not read a global that the
## garbage collector owns - a growable sequence is exactly that. So the
## caller's entropy, which may be any length, is squeezed into a fixed
## byte array before the swap, and the callback reads only that array:
##
##   caller bytes (any length) --SHAKE256--> oqsEntropySeed (64 bytes)
##                                              |
##                            callback reads ---+---> mix material
##
## Squeezing loses nothing that matters. Sixty-four bytes hold far more
## unpredictability than any generator here consumes, and the operating
## system generator is read on every call regardless, so this material
## can only add to the result, never weaken it.
##
## One property of the library is worth stating out loud: its generator
## is a single setting for the whole process, not a per-call argument.
## While this swap is in effect, any other liboqs work running on
## another thread - a signature key pair, for instance - draws from this
## generator too. That is safe (this generator reads the operating
## system on every call and only adds material on top), but it is a
## shared setting, so the counter below is stepped atomically rather
## than plainly.

const
  oqsEntropySeedBytes = 64
    ## Width of the fixed callback seed, in bytes.

var
  oqsEntropyLock: Lock
  oqsEntropySeed: array[oqsEntropySeedBytes, uint8]
  oqsEntropySeedLen: int = 0
  oqsEntropyCounter: Atomic[uint64]

discard block:
  initLock(oqsEntropyLock)
  true

proc kyberAlgId(variant: KyberTier): string =
  case variant
  of kyber0:
    result = oqsAlgKyber768
  of kyber1:
    result = oqsAlgKyber1024

proc mcElieceAlgId(variant: McElieceTier): string =
  case variant
  of mceliece0:
    result = oqsAlgClassicMcEliece6688128f
  of mceliece1:
    result = oqsAlgClassicMcEliece6960119f
  of mceliece2:
    result = oqsAlgClassicMcEliece8192128f

proc stringToBytes(s: string): seq[uint8] =
  result = newSeq[uint8](s.len)
  for i, ch in s:
    result[i] = uint8(ord(ch))

proc appendU64(buf: var seq[uint8], value: uint64) =
  for i in 0 ..< 8:
    buf.add(uint8((value shr (i * 8)) and 0xff'u64))

proc buildOqsEntropyMaterial(extraEntropy: openArray[uint8], bytesToRead: int,
    counter: uint64): seq[uint8] =
  const oqsEntropyContext = "tyr-crypto-oqs-rng-v1"
  var localMarker: uint64 = counter xor uint64(bytesToRead)
  result = newSeqOfCap[uint8](oqsEntropyContext.len + extraEntropy.len + 64)
  result.add(stringToBytes(oqsEntropyContext))
  appendU64(result, uint64(bytesToRead))
  appendU64(result, counter)
  appendU64(result, uint64(getCurrentProcessId()))
  appendU64(result, uint64(getMonoTime().ticks))
  appendU64(result, uint64(getTime().toUnix))
  appendU64(result, uint64(epochTime() * 1_000_000_000.0))
  appendU64(result, uint64(cpuTime() * 1_000_000_000.0))
  appendU64(result, cast[uint64](addr localMarker))
  result.add(extraEntropy)

proc oqsHybridRandomCallback(random_array: ptr uint8,
    bytes_to_read: csize_t) {.cdecl, gcsafe.} =
  ## Called by liboqs, on the thread that entered liboqs, while the swap
  ## lock is held. Only the fixed seed array is read from here.
  var
    counter: uint64 = 0
    mixMaterial: seq[uint8] = @[]
    randomBytes: seq[uint8] = @[]
  try:
    counter = oqsEntropyCounter.fetchAdd(1)
    mixMaterial = buildOqsEntropyMaterial(
      oqsEntropySeed.toOpenArray(0, oqsEntropySeedLen - 1),
      int(bytes_to_read), counter)
    randomBytes = cryptoRandomBytes(int(bytes_to_read), mixMaterial)
    if random_array != nil and randomBytes.len > 0:
      copyMem(random_array, unsafeAddr randomBytes[0], randomBytes.len)
  except CatchableError:
    quit(1)
  finally:
    secureClearBytes(mixMaterial)
    secureClearBytes(randomBytes)

proc loadOqsEntropySeed(extraEntropy: openArray[uint8]) =
  ## Squeezes caller entropy of any length into the fixed callback seed.
  ## No caller entropy leaves the seed empty, and the callback then mixes
  ## only its own timing and counter material.
  secureClearBytes(oqsEntropySeed)
  oqsEntropySeedLen = 0
  if extraEntropy.len == 0:
    return
  shake256Into(oqsEntropySeed, extraEntropy)
  oqsEntropySeedLen = oqsEntropySeed.len

proc withOqsHybridEntropy[T](extraEntropy: openArray[uint8],
    body: proc (): T): T =
  acquire(oqsEntropyLock)
  loadOqsEntropySeed(extraEntropy)
  oqsEntropyCounter.store(0)
  OQS_randombytes_custom_algorithm(oqsHybridRandomCallback)
  try:
    result = body()
  finally:
    discard OQS_randombytes_switch_algorithm(oqsRandAlgSystem.cstring)
    secureClearBytes(oqsEntropySeed)
    oqsEntropySeedLen = 0
    oqsEntropyCounter.store(0)
    release(oqsEntropyLock)

when defined(hasLibOqs):
  proc newKem(algId: string): ptr OqsKem =
    let kem = OQS_KEM_new(algId.cstring)
    if kem == nil:
      raiseOperation("liboqs", "KEM " & algId & " unavailable")
    result = kem

proc kemKeypair(algId: string,
    extraEntropy: openArray[uint8]): tuple[pk, sk: seq[uint8]] =
  when defined(hasLibOqs):
    result = withOqsHybridEntropy(extraEntropy, proc (): tuple[pk, sk: seq[uint8]] =
      let kem = newKem(algId)
      defer:
        OQS_KEM_free(kem)
      var pk = newSeq[uint8](int kem[].length_public_key)
      var sk = newSeq[uint8](int kem[].length_secret_key)
      requireSuccess(OQS_KEM_keypair(kem, addr pk[0], addr sk[0]),
        "OQS_KEM_keypair(" & algId & ")")
      result = (pk: pk, sk: sk)
    )
  else:
    discard algId
    discard extraEntropy
    raiseUnavailable("liboqs", "hasLibOqs")
    result = (pk: @[], sk: @[])

proc kemEncaps(algId: string,
    publicKey, extraEntropy: openArray[uint8]): tuple[ciphertext, shared: seq[uint8]] =
  when defined(hasLibOqs):
    let publicKeyBytes = @publicKey
    result = withOqsHybridEntropy(extraEntropy, proc (): tuple[ciphertext, shared: seq[uint8]] =
      let kem = newKem(algId)
      defer:
        OQS_KEM_free(kem)
      if publicKeyBytes.len != int kem[].length_public_key:
        raise newException(ValueError, "invalid " & algId & " public key length")
      var ciphertext = newSeq[uint8](int kem[].length_ciphertext)
      var shared = newSeq[uint8](int kem[].length_shared_secret)
      requireSuccess(
        OQS_KEM_encaps(
          kem,
          addr ciphertext[0],
          addr shared[0],
          if publicKeyBytes.len > 0: unsafeAddr publicKeyBytes[0] else: nil
        ),
        "OQS_KEM_encaps(" & algId & ")"
      )
      result = (ciphertext: ciphertext, shared: shared)
    )
  else:
    discard algId
    discard publicKey
    discard extraEntropy
    raiseUnavailable("liboqs", "hasLibOqs")
    result = (ciphertext: @[], shared: @[])

proc kemDecaps(algId: string, ciphertext,
    secretKey: openArray[uint8]): seq[uint8] =
  when defined(hasLibOqs):
    let kem = newKem(algId)
    defer:
      OQS_KEM_free(kem)
    if secretKey.len != int kem[].length_secret_key:
      raise newException(ValueError, "invalid " & algId & " secret key length")
    if ciphertext.len != int kem[].length_ciphertext:
      raise newException(ValueError, "invalid " & algId & " ciphertext length")
    var shared = newSeq[uint8](int kem[].length_shared_secret)
    requireSuccess(
      OQS_KEM_decaps(
        kem,
        addr shared[0],
        if ciphertext.len > 0: unsafeAddr ciphertext[0] else: nil,
        if secretKey.len > 0: unsafeAddr secretKey[0] else: nil
      ),
      "OQS_KEM_decaps(" & algId & ")"
    )
    result = shared
  else:
    discard algId
    discard ciphertext
    discard secretKey
    raiseUnavailable("liboqs", "hasLibOqs")
    result = @[]

proc x25519Keypair(): tuple[pk, sk: seq[uint8]] =
  var kp: customX25519.X25519TyrKeypair = customX25519.x25519TyrKeypair()
  result = (pk: kp.publicKey, sk: kp.secretKey)

proc x25519KeypairFromSeed(seed: openArray[uint8]): tuple[pk, sk: seq[uint8]] =
  var kp: customX25519.X25519TyrKeypair
  if seed.len != x25519KeyBytes:
    raise newException(ValueError, "invalid X25519 seed length")
  kp = customX25519.x25519TyrKeypairFromSeed(seed)
  result = (pk: kp.publicKey, sk: kp.secretKey)

proc x25519PublicKeyFromSecret(secretKey: openArray[uint8]): seq[uint8] =
  if secretKey.len != x25519KeyBytes:
    raise newException(ValueError, "invalid X25519 secret key length")
  result = customX25519.x25519TyrPublicKey(secretKey)

proc x25519Shared(secretKey, publicKey: openArray[uint8]): seq[uint8] =
  if secretKey.len != x25519KeyBytes or publicKey.len != x25519KeyBytes:
    raise newException(ValueError, "invalid X25519 key length")
  result = customX25519.x25519TyrShared(secretKey, publicKey)

proc kyberVariantForTier(alg: KemAlgorithm): KyberTier =
  case alg
  of kaKyber0:
    result = kyber0
  of kaKyber1:
    result = kyber1
  else:
    raise newException(ValueError, "algorithm is not a kyber tier")

proc mcElieceVariantForTier(alg: KemAlgorithm): McElieceTier =
  case alg
  of kaMcEliece0:
    result = mceliece0
  of kaMcEliece1:
    result = mceliece1
  of kaMcEliece2:
    result = mceliece2
  else:
    raise newException(ValueError, "algorithm is not a mceliece tier")

proc frodoAlgIdForTier(alg: KemAlgorithm): string =
  case alg
  of kaFrodo0Aes:
    result = oqsAlgFrodoKEM640Aes
  of kaFrodo0Shake:
    result = oqsAlgFrodoKEM640Shake
  of kaFrodo1Aes:
    result = oqsAlgFrodoKEM976Aes
  of kaFrodo1Shake:
    result = oqsAlgFrodoKEM976Shake
  of kaFrodo2Aes:
    result = oqsAlgFrodoKEM1344Aes
  of kaFrodo2Shake:
    result = oqsAlgFrodoKEM1344Shake
  else:
    raise newException(ValueError, "algorithm is not a frodo tier")

proc kemAlgIdForDispatch(alg: KemAlgorithm): string =
  case alg
  of kaKyber0, kaKyber1:
    result = kyberAlgId(kyberVariantForTier(alg))
  of kaMcEliece0, kaMcEliece1, kaMcEliece2:
    result = mcElieceAlgId(mcElieceVariantForTier(alg))
  of kaFrodo0Aes, kaFrodo0Shake, kaFrodo1Aes, kaFrodo1Shake, kaFrodo2Aes, kaFrodo2Shake:
    result = frodoAlgIdForTier(alg)
  of kaNtruPrime0:
    result = oqsAlgNtruPrime0
  of kaBike0:
    result = oqsAlgBike0
  else:
    raise newException(ValueError, "algorithm is not a KEM tier")

## ╭⟢ Two different things a caller can hand in
##
## `seed` and `extraEntropy` look alike and mean opposite things:
##
##   seed          "give me THIS key pair again"    -> reproducible
##   extraEntropy  "stir this in as well"           -> still unpredictable
##
## Only the routes Tyr implements itself can keep the first promise. The
## library-backed tiers draw their own randomness through liboqs, which
## offers no way to hand a seed in, so a `seed` there is refused rather
## than quietly ignored - a caller who asked for a reproducible key and
## silently got a fresh one every call would not find out until much
## later, and by then the key it was meant to reproduce would be gone.

proc refuseSeedForLibraryTier(alg: KemAlgorithm, seed: seq[uint8]) {.inline.} =
  ## alg: the tier the caller selected.
  ## seed: the material the caller offered.
  ## Fails closed when a reproducible key pair was asked of a tier that
  ## cannot produce one.
  if seed.len == 0:
    return
  raise newException(ValueError,
    "reproducible generation from a seed is not available for " & $alg &
    "; the library backend draws its own randomness. Use extraEntropy to " &
    "add material, or a Tyr-implemented tier for reproducible keys.")

proc genKeypair*(alg: KemAlgorithm, seed: seq[uint8] = @[],
    extraEntropy: seq[uint8] = @[]): AsymKeypair =
  ## alg: which key-exchange tier to build a key pair for.
  ## seed: reproducible key material. Supported by the Tyr-implemented
  ##   routes; the library-backed tiers refuse it.
  ## extraEntropy: extra material folded into the system generator. It
  ##   cannot weaken the result and helps on devices whose entropy pool is
  ##   thin at boot. The result stays unpredictable.
  var
    kp0: tuple[pk, sk: seq[uint8]]
    algId: string = ""
  case alg
  of kaX25519:
    if seed.len > 0:
      kp0 = x25519KeypairFromSeed(seed)
    else:
      kp0 = x25519Keypair()
    result.publicKey = kp0.pk
    result.secretKey = kp0.sk
  of kaKyber0, kaKyber1, kaMcEliece0, kaMcEliece1, kaMcEliece2,
      kaFrodo0Aes, kaFrodo0Shake, kaFrodo1Aes, kaFrodo1Shake, kaFrodo2Aes,
      kaFrodo2Shake, kaNtruPrime0, kaBike0:
    refuseSeedForLibraryTier(alg, seed)
    algId = kemAlgIdForDispatch(alg)
    kp0 = kemKeypair(algId, extraEntropy)
    result.publicKey = kp0.pk
    result.secretKey = kp0.sk

proc genKeypair*(T: typedesc[mceliece0TyrSendM]): AsymKeypair =
  ## Build a pure-Nim Tyr McEliece tier-0 keypair.
  var kp = customMcEliece.mcelieceTyrKeypair(customMcEliece.mceliece6688128f)
  result.publicKey = kp.publicKey
  result.secretKey = kp.secretKey

proc genKeypair*(T: typedesc[kyber0TyrSendM]): AsymKeypair =
  ## Build a pure-Nim Tyr Kyber tier-0 keypair.
  var kp = customKyber.kyberTyrKeypair(customKyber.kyber768)
  result.publicKey = kp.publicKey
  result.secretKey = kp.secretKey

proc genKeypair*(T: typedesc[kyber0TyrOpenM]): AsymKeypair =
  ## Build a pure-Nim Tyr Kyber tier-0 keypair.
  result = genKeypair(kyber0TyrSendM)

proc genKeypair*(T: typedesc[kyber1TyrSendM]): AsymKeypair =
  ## Build a pure-Nim Tyr Kyber tier-1 keypair.
  var kp = customKyber.kyberTyrKeypair(customKyber.kyber1024)
  result.publicKey = kp.publicKey
  result.secretKey = kp.secretKey

proc genKeypair*(T: typedesc[kyber1TyrOpenM]): AsymKeypair =
  ## Build a pure-Nim Tyr Kyber tier-1 keypair.
  result = genKeypair(kyber1TyrSendM)

proc genKeypair*(T: typedesc[mceliece0TyrOpenM]): AsymKeypair =
  ## Build a pure-Nim Tyr McEliece tier-0 keypair.
  result = genKeypair(mceliece0TyrSendM)

proc genKeypair*(T: typedesc[mceliece1TyrSendM]): AsymKeypair =
  ## Build a pure-Nim Tyr McEliece tier-1 keypair.
  var kp = customMcEliece.mcelieceTyrKeypair(customMcEliece.mceliece6960119f)
  result.publicKey = kp.publicKey
  result.secretKey = kp.secretKey

proc genKeypair*(T: typedesc[mceliece1TyrOpenM]): AsymKeypair =
  ## Build a pure-Nim Tyr McEliece tier-1 keypair.
  result = genKeypair(mceliece1TyrSendM)

proc genKeypair*(T: typedesc[mceliece2TyrSendM]): AsymKeypair =
  ## Build a pure-Nim Tyr McEliece tier-2 keypair.
  var kp = customMcEliece.mcelieceTyrKeypair(customMcEliece.mceliece8192128f)
  result.publicKey = kp.publicKey
  result.secretKey = kp.secretKey

proc genKeypair*(T: typedesc[mceliece2TyrOpenM]): AsymKeypair =
  ## Build a pure-Nim Tyr McEliece tier-2 keypair.
  result = genKeypair(mceliece2TyrSendM)

proc buildFrodoTyrKeypair(v: customFrodo.FrodoVariant): AsymKeypair =
  var kp = customFrodo.frodoTyrKeypair(v)
  result.publicKey = kp.publicKey
  result.secretKey = kp.secretKey

proc genKeypair*(T: typedesc[frodo0AesTyrSendM]): AsymKeypair =
  result = buildFrodoTyrKeypair(customFrodo.frodo640aes)

proc genKeypair*(T: typedesc[frodo0AesTyrOpenM]): AsymKeypair =
  result = genKeypair(frodo0AesTyrSendM)

proc genKeypair*(T: typedesc[frodo0ShakeTyrSendM]): AsymKeypair =
  result = buildFrodoTyrKeypair(customFrodo.frodo640shake)

proc genKeypair*(T: typedesc[frodo0ShakeTyrOpenM]): AsymKeypair =
  result = genKeypair(frodo0ShakeTyrSendM)

proc genKeypair*(T: typedesc[frodo1AesTyrSendM]): AsymKeypair =
  result = buildFrodoTyrKeypair(customFrodo.frodo976aes)

proc genKeypair*(T: typedesc[frodo1AesTyrOpenM]): AsymKeypair =
  result = genKeypair(frodo1AesTyrSendM)

proc genKeypair*(T: typedesc[frodo1ShakeTyrSendM]): AsymKeypair =
  result = buildFrodoTyrKeypair(customFrodo.frodo976shake)

proc genKeypair*(T: typedesc[frodo1ShakeTyrOpenM]): AsymKeypair =
  result = genKeypair(frodo1ShakeTyrSendM)

proc genKeypair*(T: typedesc[frodo2AesTyrSendM]): AsymKeypair =
  result = buildFrodoTyrKeypair(customFrodo.frodo1344aes)

proc genKeypair*(T: typedesc[frodo2AesTyrOpenM]): AsymKeypair =
  result = genKeypair(frodo2AesTyrSendM)

proc genKeypair*(T: typedesc[frodo2ShakeTyrSendM]): AsymKeypair =
  result = buildFrodoTyrKeypair(customFrodo.frodo1344shake)

proc genKeypair*(T: typedesc[frodo2ShakeTyrOpenM]): AsymKeypair =
  result = genKeypair(frodo2ShakeTyrSendM)

proc genKeypair*(T: typedesc[bike0TyrSendM]): AsymKeypair =
  ## Build a pure-Nim Tyr BIKE tier-0 keypair.
  var kp = customBike.bikeTyrKeypair(customBike.bikeL1)
  result.publicKey = kp.publicKey
  result.secretKey = kp.secretKey

proc genKeypair*(T: typedesc[bike0TyrOpenM]): AsymKeypair =
  ## Build a pure-Nim Tyr BIKE tier-0 keypair.
  result = genKeypair(bike0TyrSendM)

## ╭⟢ Encapsulating and decapsulating by tier value

proc encaps*(alg: KemAlgorithm, receiverPublicKey: seq[uint8],
    senderPublicKey: seq[uint8] = @[], senderSecretKey: seq[uint8] = @[],
    seed: seq[uint8] = @[], extraEntropy: seq[uint8] = @[]): AsymCipher =
  ## Encapsulate or derive a shared secret for the selected KEM/X25519 backend.
  ## X25519 may either generate an ephemeral sender keypair or reuse the provided one.
  ## seed: reproducible sender material, X25519 only. The library-backed
  ##   tiers refuse it, for the reason stated above `genKeypair`.
  ## extraEntropy: extra material folded into the system generator on the
  ##   library-backed tiers. The result stays unpredictable.
  var
    kp0: tuple[pk, sk: seq[uint8]]
    kem0: tuple[ciphertext, shared: seq[uint8]]
    algId: string = ""
  case alg
  of kaX25519:
    if senderPublicKey.len == 0 and senderSecretKey.len == 0:
      if seed.len > 0:
        kp0 = x25519KeypairFromSeed(seed)
      else:
        kp0 = x25519Keypair()
    elif senderPublicKey.len > 0 and senderSecretKey.len > 0:
      let derivedPublicKey = x25519PublicKeyFromSecret(senderSecretKey)
      if not constantTimeEqual(derivedPublicKey, senderPublicKey):
        raise newException(ValueError,
          "x25519 senderPublicKey does not match senderSecretKey")
      kp0 = (pk: senderPublicKey, sk: senderSecretKey)
    else:
      raise newException(ValueError,
        "x25519 dispatch requires both senderPublicKey and senderSecretKey, or neither")
    result = initAsymCipher(@[], kp0.pk, x25519Shared(kp0.sk, receiverPublicKey))
  of kaKyber0, kaKyber1, kaMcEliece0, kaMcEliece1, kaMcEliece2,
      kaFrodo0Aes, kaFrodo0Shake, kaFrodo1Aes, kaFrodo1Shake, kaFrodo2Aes,
      kaFrodo2Shake, kaNtruPrime0, kaBike0:
    refuseSeedForLibraryTier(alg, seed)
    algId = kemAlgIdForDispatch(alg)
    kem0 = kemEncaps(algId, receiverPublicKey, extraEntropy)
    result = initAsymCipher(kem0.ciphertext, @[], kem0.shared)

proc decaps*(alg: KemAlgorithm, receiverSecretKey: seq[uint8],
    cipher: AsymEnvelope): seq[uint8] =
  ## Recover the shared secret from a previously returned asymmetric envelope.
  var algId: string = ""
  case alg
  of kaX25519:
    result = x25519Shared(receiverSecretKey, cipher.senderPublicKey)
  of kaKyber0, kaKyber1, kaMcEliece0, kaMcEliece1, kaMcEliece2,
      kaFrodo0Aes, kaFrodo0Shake, kaFrodo1Aes, kaFrodo1Shake, kaFrodo2Aes,
      kaFrodo2Shake, kaNtruPrime0, kaBike0:
    algId = kemAlgIdForDispatch(alg)
    result = kemDecaps(algId, cipher.ciphertext, receiverSecretKey)

proc decaps*(alg: KemAlgorithm, receiverSecretKey: seq[uint8],
    cipher: AsymCipher): seq[uint8] =
  ## Recover the shared secret using a local `AsymCipher` result.
  result = decaps(alg, receiverSecretKey, cipher.envelope)

## ╭⟢ Sealing and opening from typed material

proc seal*(m: x25519SendM): AsymCipher =
  ## Encapsulate or derive a shared secret using typed X25519 send material.
  result = encaps(kaX25519, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: x25519OpenM): seq[byte] =
  ## Recover a shared secret using typed X25519 open material.
  result = decaps(kaX25519, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: kyber0SendM): AsymCipher =
  result = encaps(kaKyber0, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: kyber0OpenM): seq[byte] =
  result = decaps(kaKyber0, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: kyber1SendM): AsymCipher =
  result = encaps(kaKyber1, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: kyber1OpenM): seq[byte] =
  result = decaps(kaKyber1, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: kyber0TyrSendM): AsymCipher =
  ## Encapsulate with the pure-Nim Tyr Kyber tier-0 backend.
  var env = customKyber.kyberTyrEncaps(customKyber.kyber768, toSeqBytes(m.receiverPublicKey))
  result.envelope.ciphertext = env.ciphertext
  result.envelope.senderPublicKey = @[]
  result.sharedSecret = env.sharedSecret

proc open*(env: AsymEnvelope, m: kyber0TyrOpenM): seq[byte] =
  ## Decapsulate with the pure-Nim Tyr Kyber tier-0 backend.
  result = customKyber.kyberTyrDecaps(customKyber.kyber768,
    toSeqBytes(m.receiverSecretKey), env.ciphertext)

proc seal*(m: kyber1TyrSendM): AsymCipher =
  ## Encapsulate with the pure-Nim Tyr Kyber tier-1 backend.
  var env = customKyber.kyberTyrEncaps(customKyber.kyber1024, toSeqBytes(m.receiverPublicKey))
  result.envelope.ciphertext = env.ciphertext
  result.envelope.senderPublicKey = @[]
  result.sharedSecret = env.sharedSecret

proc open*(env: AsymEnvelope, m: kyber1TyrOpenM): seq[byte] =
  ## Decapsulate with the pure-Nim Tyr Kyber tier-1 backend.
  result = customKyber.kyberTyrDecaps(customKyber.kyber1024,
    toSeqBytes(m.receiverSecretKey), env.ciphertext)

proc seal*(m: mceliece0SendM): AsymCipher =
  result = encaps(kaMcEliece0, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: mceliece0OpenM): seq[byte] =
  result = decaps(kaMcEliece0, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: mceliece1SendM): AsymCipher =
  result = encaps(kaMcEliece1, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: mceliece1OpenM): seq[byte] =
  result = decaps(kaMcEliece1, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: mceliece2SendM): AsymCipher =
  result = encaps(kaMcEliece2, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: mceliece2OpenM): seq[byte] =
  result = decaps(kaMcEliece2, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: mceliece0TyrSendM): AsymCipher =
  ## Encapsulate with the pure-Nim Tyr McEliece tier-0 backend.
  var env = customMcEliece.mcelieceTyrEncaps(customMcEliece.mceliece6688128f,
    toSeqBytes(m.receiverPublicKey))
  result.envelope.ciphertext = env.ciphertext
  result.envelope.senderPublicKey = @[]
  result.sharedSecret = env.sharedSecret

proc open*(env: AsymEnvelope, m: mceliece0TyrOpenM): seq[byte] =
  ## Decapsulate with the pure-Nim Tyr McEliece tier-0 backend.
  result = customMcEliece.mcelieceTyrDecaps(customMcEliece.mceliece6688128f,
    toSeqBytes(m.receiverSecretKey), env.ciphertext)

proc seal*(m: mceliece1TyrSendM): AsymCipher =
  ## Encapsulate with the pure-Nim Tyr McEliece tier-1 backend.
  var env = customMcEliece.mcelieceTyrEncaps(customMcEliece.mceliece6960119f,
    toSeqBytes(m.receiverPublicKey))
  result.envelope.ciphertext = env.ciphertext
  result.envelope.senderPublicKey = @[]
  result.sharedSecret = env.sharedSecret

proc open*(env: AsymEnvelope, m: mceliece1TyrOpenM): seq[byte] =
  ## Decapsulate with the pure-Nim Tyr McEliece tier-1 backend.
  result = customMcEliece.mcelieceTyrDecaps(customMcEliece.mceliece6960119f,
    toSeqBytes(m.receiverSecretKey), env.ciphertext)

proc seal*(m: mceliece2TyrSendM): AsymCipher =
  ## Encapsulate with the pure-Nim Tyr McEliece tier-2 backend.
  var env = customMcEliece.mcelieceTyrEncaps(customMcEliece.mceliece8192128f,
    toSeqBytes(m.receiverPublicKey))
  result.envelope.ciphertext = env.ciphertext
  result.envelope.senderPublicKey = @[]
  result.sharedSecret = env.sharedSecret

proc open*(env: AsymEnvelope, m: mceliece2TyrOpenM): seq[byte] =
  ## Decapsulate with the pure-Nim Tyr McEliece tier-2 backend.
  result = customMcEliece.mcelieceTyrDecaps(customMcEliece.mceliece8192128f,
    toSeqBytes(m.receiverSecretKey), env.ciphertext)

proc buildFrodoTyrSeal(v: customFrodo.FrodoVariant, pk: openArray[byte]): AsymCipher =
  var env = customFrodo.frodoTyrEncaps(v, toSeqBytes(pk))
  result.envelope.ciphertext = env.ciphertext
  result.envelope.senderPublicKey = @[]
  result.sharedSecret = env.sharedSecret

proc buildFrodoTyrOpen(v: customFrodo.FrodoVariant, sk: openArray[byte],
    env: AsymEnvelope): seq[byte] =
  result = customFrodo.frodoTyrDecaps(v, toSeqBytes(sk), env.ciphertext)

proc seal*(m: frodo0AesSendM): AsymCipher =
  result = encaps(kaFrodo0Aes, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: frodo0AesOpenM): seq[byte] =
  result = decaps(kaFrodo0Aes, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: frodo0ShakeSendM): AsymCipher =
  result = encaps(kaFrodo0Shake, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: frodo0ShakeOpenM): seq[byte] =
  result = decaps(kaFrodo0Shake, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: frodo1AesSendM): AsymCipher =
  result = encaps(kaFrodo1Aes, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: frodo1AesOpenM): seq[byte] =
  result = decaps(kaFrodo1Aes, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: frodo1ShakeSendM): AsymCipher =
  result = encaps(kaFrodo1Shake, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: frodo1ShakeOpenM): seq[byte] =
  result = decaps(kaFrodo1Shake, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: frodo2AesSendM): AsymCipher =
  result = encaps(kaFrodo2Aes, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: frodo2AesOpenM): seq[byte] =
  result = decaps(kaFrodo2Aes, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: frodo2ShakeSendM): AsymCipher =
  result = encaps(kaFrodo2Shake, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: frodo2ShakeOpenM): seq[byte] =
  result = decaps(kaFrodo2Shake, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: frodo0AesTyrSendM): AsymCipher =
  result = buildFrodoTyrSeal(customFrodo.frodo640aes, m.receiverPublicKey)

proc open*(env: AsymEnvelope, m: frodo0AesTyrOpenM): seq[byte] =
  result = buildFrodoTyrOpen(customFrodo.frodo640aes, m.receiverSecretKey, env)

proc seal*(m: frodo0ShakeTyrSendM): AsymCipher =
  result = buildFrodoTyrSeal(customFrodo.frodo640shake, m.receiverPublicKey)

proc open*(env: AsymEnvelope, m: frodo0ShakeTyrOpenM): seq[byte] =
  result = buildFrodoTyrOpen(customFrodo.frodo640shake, m.receiverSecretKey, env)

proc seal*(m: frodo1AesTyrSendM): AsymCipher =
  result = buildFrodoTyrSeal(customFrodo.frodo976aes, m.receiverPublicKey)

proc open*(env: AsymEnvelope, m: frodo1AesTyrOpenM): seq[byte] =
  result = buildFrodoTyrOpen(customFrodo.frodo976aes, m.receiverSecretKey, env)

proc seal*(m: frodo1ShakeTyrSendM): AsymCipher =
  result = buildFrodoTyrSeal(customFrodo.frodo976shake, m.receiverPublicKey)

proc open*(env: AsymEnvelope, m: frodo1ShakeTyrOpenM): seq[byte] =
  result = buildFrodoTyrOpen(customFrodo.frodo976shake, m.receiverSecretKey, env)

proc seal*(m: frodo2AesTyrSendM): AsymCipher =
  result = buildFrodoTyrSeal(customFrodo.frodo1344aes, m.receiverPublicKey)

proc open*(env: AsymEnvelope, m: frodo2AesTyrOpenM): seq[byte] =
  result = buildFrodoTyrOpen(customFrodo.frodo1344aes, m.receiverSecretKey, env)

proc seal*(m: frodo2ShakeTyrSendM): AsymCipher =
  result = buildFrodoTyrSeal(customFrodo.frodo1344shake, m.receiverPublicKey)

proc open*(env: AsymEnvelope, m: frodo2ShakeTyrOpenM): seq[byte] =
  result = buildFrodoTyrOpen(customFrodo.frodo1344shake, m.receiverSecretKey, env)

proc seal*(m: ntruprime0SendM): AsymCipher =
  result = encaps(kaNtruPrime0, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: ntruprime0OpenM): seq[byte] =
  result = decaps(kaNtruPrime0, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: bike0SendM): AsymCipher =
  result = encaps(kaBike0, toSeqBytes(m.receiverPublicKey))

proc open*(env: AsymEnvelope, m: bike0OpenM): seq[byte] =
  result = decaps(kaBike0, toSeqBytes(m.receiverSecretKey), env)

proc seal*(m: bike0TyrSendM): AsymCipher =
  ## Encapsulate with the pure-Nim Tyr BIKE tier-0 backend.
  var env = customBike.bikeTyrEncaps(customBike.bikeL1, toSeqBytes(m.receiverPublicKey))
  result.envelope.ciphertext = env.ciphertext
  result.envelope.senderPublicKey = @[]
  result.sharedSecret = env.sharedSecret

proc open*(env: AsymEnvelope, m: bike0TyrOpenM): seq[byte] =
  ## Decapsulate with the pure-Nim Tyr BIKE tier-0 backend.
  result = customBike.bikeTyrDecaps(customBike.bikeL1,
    toSeqBytes(m.receiverSecretKey), env.ciphertext)

proc open*[T](cipher: AsymCipher, m: T): seq[byte] =
  ## Recover a shared secret from the public envelope inside a local result.
  result = open(cipher.envelope, m)

proc seal*[A, B](a: A, b: B): array[2, AsymCipher] =
  ## Convenience helper for composing two independent KEM/ECDH sends.
  result[0] = seal(a)
  result[1] = seal(b)

proc seal*[A, B, C](a: A, b: B, c: C): array[3, AsymCipher] =
  ## Convenience helper for composing three independent KEM/ECDH sends.
  result[0] = seal(a)
  result[1] = seal(b)
  result[2] = seal(c)

proc open*[A, B](envs: array[2, AsymEnvelope], a: A, b: B): array[2, seq[byte]] =
  ## Convenience helper for opening two public KEM/ECDH envelopes.
  result[0] = open(envs[0], a)
  result[1] = open(envs[1], b)

proc open*[A, B](ciphers: array[2, AsymCipher], a: A, b: B): array[2, seq[byte]] =
  ## Convenience helper for opening two local KEM/ECDH results.
  result[0] = open(ciphers[0], a)
  result[1] = open(ciphers[1], b)

proc open*[A, B, C](envs: array[3, AsymEnvelope], a: A, b: B,
    c: C): array[3, seq[byte]] =
  ## Convenience helper for opening three public KEM/ECDH envelopes.
  result[0] = open(envs[0], a)
  result[1] = open(envs[1], b)
  result[2] = open(envs[2], c)

proc open*[A, B, C](ciphers: array[3, AsymCipher], a: A, b: B,
    c: C): array[3, seq[byte]] =
  ## Convenience helper for opening three local KEM/ECDH results.
  result[0] = open(ciphers[0], a)
  result[1] = open(ciphers[1], b)
  result[2] = open(ciphers[2], c)
