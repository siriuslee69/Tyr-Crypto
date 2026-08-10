import tyr_crypto

var m: xchacha20TyrCipherM
for i in 0 ..< m.key.len:    m.key[i] = 0x11'u8
for i in 0 ..< m.nonce.len:  m.nonce[i] = 0x22'u8

let msg = @[byte 'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd']

let cipher = encrypt(msg, m)
let plain = decrypt(cipher, m)
doAssert plain == msg
echo "AEAD roundtrip OK: ", plain
