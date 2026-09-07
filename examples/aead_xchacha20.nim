## XChaCha20 + keyed BLAKE3 <- seal -> open
##
## AEAD means the same call both hides the message and proves nobody
## changed it. `seal` returns two pieces:
##
##   plaintext --xor keystream--> ciphertext --keyed hash--> auth (tag)
##
## `open` checks the tag FIRST and refuses a changed ciphertext before
## decrypting a single byte. The last block below shows that refusal.
##
## `wrapper.nim` does the same job through the typed material wrapper;
## this file uses the suite API directly.
import tyr

## This suite wants two 32-byte keys, in the order `keyCount` documents:
## one for the XChaCha20 layer, then one for the BLAKE3 tag.
var
  cipherKey: seq[uint8] = newSeq[uint8](32)
  macKey: seq[uint8] = newSeq[uint8](32)
  nonce: seq[uint8] = newSeq[uint8](nonceBytes(csXChaCha20Blake3))
  msg: seq[uint8] = @[]
  state: AeadState = nil
  sealed: AeadCiphertext = AeadCiphertext()
  plain: seq[uint8] = @[]
  tampered: AeadCiphertext = AeadCiphertext()
  refused: bool = false

## A real caller draws these from the operating system. Fixed bytes here
## keep the example reproducible; never reuse a nonce with the same key.
for i in 0 ..< cipherKey.len:
  cipherKey[i] = uint8(i)
for i in 0 ..< macKey.len:
  macKey[i] = uint8(0x40 + i)
for i in 0 ..< nonce.len:
  nonce[i] = uint8(0xA0 + i)
for ch in "Tyr seals with XChaCha20":
  msg.add uint8(ord(ch))

state = initAeadState(csXChaCha20Blake3, @[cipherKey, macKey], nonce)
sealed = seal(msg, state)
plain = open(sealed, state)

assert plain == msg, "AEAD roundtrip mismatch"
echo "ciphertext bytes: ", sealed.ciphertext.len, "  tag bytes: ", sealed.auth.len
echo "opened: ", cast[string](plain)

## Flip one ciphertext bit and the tag no longer matches.
tampered = sealed
tampered.ciphertext[0] = tampered.ciphertext[0] xor 0x01'u8
try:
  discard open(tampered, state)
except CatchableError:
  refused = true

assert refused, "a changed ciphertext must not open"
echo "tampered ciphertext refused: ", refused
