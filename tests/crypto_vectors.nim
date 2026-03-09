type
  AeadVector* = object
    keyHex*: string
    nonceHex*: string
    adHex*: string
    message*: string
    cipherHex*: string

  ScalarmultVector* = object
    skHex*: string
    pkHex*: string
    sharedHex*: string

  Argon2Vector* = object
    password*: string
    encoded*: string
    shouldPass*: bool

  WrapperXChaChaVector* = object
    keyHex*: string
    nonceHex*: string
    plaintextHex*: string
    cipherHex*: string
    tagHex*: string

const
  xchacha20Poly1305Vector* = AeadVector(
    keyHex: "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    nonceHex: "07000000404142434445464748494a4b4c4d4e4f50515253",
    adHex: "50515253c0c1c2c3c4c5c6c7",
    message: "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
    cipherHex: "f8ebea4875044066fc162a0604e171feecfb3d20425248563bcfd5a155dcc47bbda70b86e5ab9b55002bd1274c02db35321acd7af8b2e2d25015e136b7679458e9f43243bf719d639badb5feac03f80a19a96ef10cb1d15333a837b90946ba3854ee74da3f2585efc7e1e170e17e15e563e77601f4f85cafa8e5877614e143e68420"
  )

  curve25519Vector* = ScalarmultVector(
    pkHex: "9c647d9ae589b9f58fdc3ca4947efbc915c4b2e08e744a0edf469dac59c8f85a",
    skHex: "4852834d9d6b77dadeabaaf2e11dca66d19fe74993a7bec36c6e16a0983feaba",
    sharedHex: "87b7f212b627f7a54ca5e0bcdaddd5389d9de6156cdbcf8ebe14ffbcfb436551"
  )

  argon2idVectors* = [
    Argon2Vector(
      password: "",
      encoded: "$argon2id$v=19$m=4096,t=0,p=1$X1NhbHQAAAAAAAAAAAAAAA$bWh++MKN1OiFHKgIWTLvIi1iHicmHH7+Fv3K88ifFfI",
      shouldPass: false
    ),
    Argon2Vector(
      password: "",
      encoded: "$argon2id$v=19$m=2048,t=4,p=1$SWkxaUhpY21ISDcrRnYzSw$Mbg/Eck1kpZir5T9io7C64cpffdTBaORgyriLQFgQj8",
      shouldPass: false
    ),
    Argon2Vector(
      password: "",
      encoded: "$argon2id$v=19$m=4882,t=2,p=1$bA81arsiXysd3WbTRzmEOw$Nm8QBM+7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
      shouldPass: true
    ),
    Argon2Vector(
      password: "^T5H$JYt39n%K*j:W]!1s?vg!:jGi]Ax?..l7[p0v:1jHTpla9;]bUN;?bWyCbtqg ",
      encoded: "$argon2id$v=19$m=4096,t=0,p=1$PkEgMTYtYnl0ZXMgc2FsdA$ltB/ue1kPtBMBGfsysMpPigE6hiNEKZ9vs8vLNVDQGA",
      shouldPass: false
    ),
    Argon2Vector(
      password: "^T5H$JYt39n%K*j:W]!1s?vg!:jGi]Ax?..l7[p0v:1jHTpla9;]bUN;?bWyCbtqg ",
      encoded: "$argon2id$v=19$m=4096,t=19,p=1$PkEgMTYtYnl0ZXMgc2FsdA$ltB/ue1kPtBMBGfsysMpPigE6hiNEKZ9vs8vLNVDQGA",
      shouldPass: true
    ),
    Argon2Vector(
      password: "K3S=KyH#)36_?]LxeR8QNKw6X=gFbxai$C%29V*",
      encoded: "$argon2id$v=19$m=4096,t=1,p=3$PkEgcHJldHR5IGxvbmcgc2FsdA$HUqx5Z1b/ZypnUrvvJ5UC2Q+T6Q1WwASK/Kr9dRbGA0",
      shouldPass: true
    )
  ]

  wrapperXChaChaVector* = WrapperXChaChaVector(
    keyHex: "79c99798ac67300bbb2704c95c341e3245f3dcb21761b98e52ff45b24f304fc4",
    nonceHex: "b33ffd3096479bcfbc9aee49417688a0a2554f8d95389419",
    plaintextHex: "0000000000000000000000000000000000000000000000000000000000",
    cipherHex: "c6e9758160083ac604ef90e712ce6e75d7797590744e0cf060f013739c",
    tagHex: "4bbde0b4052b3b5ec16deeaf18806fd0483c824f781d3dba554a8207cb88bd30"
  )
