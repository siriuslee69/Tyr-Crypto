import std/unittest
import ../src/tyr_crypto/wrapper/hybrid_kex_triple
import ../src/tyr_crypto/algorithms
import ../src/tyr_crypto/common

suite "hybrid kex":
  when defined(hasLibOqs) and defined(hasLibsodium):
    test "Kyber + McEliece + X25519 shared secret matches":
      if not hybridKexAvailable():
        check true
      else:
        let state = createHybridKexOffer()
        let (response, sharedResponder) = respondHybridKexOffer(state.offer)
        let sharedInitiator = finalizeHybridKex(state, response)
        check sharedResponder == sharedInitiator
        check sharedResponder.len == 32

    test "hybrid kex accepts caller entropy":
      if not hybridKexAvailable():
        check true
      else:
        let state = createHybridKexOfferWithEntropy(kvKyber768,
          mvClassicMcEliece6688128, "mouse-jitter;req=84")
        let (response, sharedResponder) = respondHybridKexOfferWithEntropy(
          state.offer, "keypress-latency;req=84")
        let sharedInitiator = finalizeHybridKex(state, response)
        check sharedResponder == sharedInitiator
        check sharedResponder.len == 32

    test "custom hybrid variants roundtrip":
      if not hybridKexAvailable(kvKyber1024, mvClassicMcEliece6960119):
        check true
      else:
        let state = createHybridKexOffer(kvKyber1024, mvClassicMcEliece6960119)
        let (response, sharedResponder) = respondHybridKexOffer(state.offer)
        let sharedInitiator = finalizeHybridKex(state, response)
        check state.offer.kyberVariant == kvKyber1024
        check state.offer.mcElieceVariant == mvClassicMcEliece6960119
        check sharedResponder == sharedInitiator
        check sharedResponder.len == 32
  else:
    test "hybrid kex unavailable raises descriptive error":
      expect LibraryUnavailableError:
        discard createHybridKexOffer()

    test "hybrid kex entropy helper unavailable raises descriptive error":
      expect LibraryUnavailableError:
        discard createHybridKexOfferWithEntropy(kvKyber768,
          mvClassicMcEliece6688128, "user-entropy")
