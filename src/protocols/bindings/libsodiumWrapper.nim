import ./libsodium
import std/sysrand

type 
  AlgoType = enum
    chacha20, aes256
  State[T: static[AlgoType]] = object 
    when T == chacha20:
      key: array[int(crypto_aead_xchacha20poly1305_ietf_keybytes()), uint8]
      nonce: seq[uint8]


proc initKey*(a: static[AlgoType]): seq[uint8] =
  ensureSodiumInitialised()
  if a == chacha20:
    const l: int = int(crypto_aead_xchacha20poly1305_ietf_keybytes())
    result = ( urandom(l) )
  else:
    static:
      doAssert false, "Unsupported algorithm for initKey"

proc initNonce*(a: static[AlgoType]): seq[uint8] =
  ensureSodiumInitialised()
  when a == chacha20:
    const l: int = int(crypto_aead_xchacha20poly1305_ietf_npubbytes())
    result = ( urandom(l) )
  else:
    static:
      doAssert false, "Unsupported algorithm for initNonce"

proc init*(a: static[AlgoType], k: seq[uint8]): State[a] =
  when a == chacha20:
    State[a](key: initKey(a), nonce: initNonce(a))
  else:
    static:
      doAssert false, "Unsupported algorithm for init"


proc encrypt*(data: openArray[byte], s: State[chacha20], a: static[AlgoType] = chacha20): seq[uint8] =
  when a == chacha20:
    ensureSodiumInitialised()
    if s.key.len != int(crypto_aead_xchacha20poly1305_ietf_keybytes()):
      raise newException(ValueError, "invalid chacha20 key length")
    if s.nonce.len != int(crypto_aead_xchacha20poly1305_ietf_npubbytes()):
      raise newException(ValueError, "invalid chacha20 nonce length")
    var clen: culonglong
    var buf = newSeq[uint8](data.len + 16)
    let dataPtr = if data.len == 0: nil else: unsafeAddr data[0]
    let res = crypto_aead_xchacha20poly1305_ietf_encrypt(
      addr buf[0],
      addr clen,
      dataPtr,
      culonglong(data.len),
      nil,
      0,
      nil,
      addr s.nonce[0],
      addr s.key[0]
    )
    if res != 0:
      raise newException(ValueError, "libsodium xchacha20poly1305 encryption failed")
    buf.setLen(int(clen))
    return buf
  else:
    static:
      doAssert false, "Unsupported algorithm for encrypt"

proc encrypt*(data: openArray[byte], s: State[chacha20]): seq[uint8] =
  encrypt(data, s, chacha20)
