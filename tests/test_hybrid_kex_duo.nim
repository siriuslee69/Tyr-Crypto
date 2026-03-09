import std/unittest
import ../src/tyr_crypto/wrapper/hybrid_kex_duo
import ../src/tyr_crypto/algorithms
import ../src/tyr_crypto/common

suite "hybrid kex duo":
  when defined(hasLibOqs) and defined(hasLibsodium):
    test "Kyber + X25519 shared secret matches":
      if not kyberX25519KexAvailable():
        check true
      else:
        let state = createKyberX25519KexOffer()
        let (response, sharedResponder) = respondKyberX25519KexOffer(state.offer)
        let sharedInitiator = finalizeKyberX25519Kex(state, response)
        check sharedResponder == sharedInitiator
        check sharedResponder.len == 32

    test "Kyber + X25519 accepts caller entropy":
      if not kyberX25519KexAvailable():
        check true
      else:
        let state = createKyberX25519KexOfferWithEntropy(kvKyber768,
          "mouse-jitter;req=42")
        let (response, sharedResponder) = respondKyberX25519KexOfferWithEntropy(
          state.offer, "keypress-latency;req=42")
        let sharedInitiator = finalizeKyberX25519Kex(state, response)
        check sharedResponder == sharedInitiator
        check sharedResponder.len == 32

    test "Kyber1024 + X25519 shared secret matches":
      if not kyberX25519KexAvailable(kvKyber1024):
        check true
      else:
        let state = createKyberX25519KexOffer(kvKyber1024)
        let (response, sharedResponder) = respondKyberX25519KexOffer(state.offer)
        let sharedInitiator = finalizeKyberX25519Kex(state, response)
        check state.offer.kyberVariant == kvKyber1024
        check sharedResponder == sharedInitiator
        check sharedResponder.len == 32

    test "McEliece + X25519 shared secret matches":
      if not mcElieceX25519KexAvailable():
        check true
      else:
        let state = createMcElieceX25519KexOffer()
        let (response, sharedResponder) = respondMcElieceX25519KexOffer(state.offer)
        let sharedInitiator = finalizeMcElieceX25519Kex(state, response)
        check sharedResponder == sharedInitiator
        check sharedResponder.len == 32

    test "alternate McEliece variant can be selected":
      if not mcElieceX25519KexAvailable(mvClassicMcEliece6960119):
        check true
      else:
        let state = createMcElieceX25519KexOffer(mvClassicMcEliece6960119)
        check state.offer.mcElieceVariant == mvClassicMcEliece6960119
  else:
    test "hybrid kex unavailable raises descriptive error":
      expect LibraryUnavailableError:
        discard createKyberX25519KexOffer()

    test "hybrid kex entropy helper unavailable raises descriptive error":
      expect LibraryUnavailableError:
        discard createKyberX25519KexOfferWithEntropy(kvKyber768, "user-entropy")
