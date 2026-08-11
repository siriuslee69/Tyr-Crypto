import std/strutils
import tyr

var m: xchacha20TyrCipherM
for i in 0 ..< m.key.len:    m.key[i] = 0x11'u8
for i in 0 ..< m.nonce.len:  m.nonce[i] = 0x22'u8

let msg = @[byte 'H', byte 'e', byte 'l', byte 'l', byte 'o', byte ' ', byte 'W', byte 'o', byte 'r', byte 'l', byte 'd']

let cipher = encrypt(msg, m)
let plain = decrypt(cipher, m)
doAssert plain == msg
echo "AEAD roundtrip OK: ", plain
