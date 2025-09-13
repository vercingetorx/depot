# kyber.nim — simple, readable Kyber API
# Flow (at a glance):
#   1) Each person makes a KeyPair and shares ONLY their publicKey.
#   2) Sender calls createEnvelope(recipientPublicKey) → (envelope, sessionKey).
#      - Send the envelope to the recipient (public).
#      - Keep the sessionKey secret (use it for encryption/MAC).
#   3) Recipient calls openEnvelope(myPrivateKey, envelope) → sessionKey.
#      - Both sides now hold the same sessionKey.
# Notes:
#   - Optional `coins` let you make results deterministic for tests (64B for keypair, 32B for encapsulation).

import src/[params, kem]

type
  KeyPair* = object
    publicKey*:  seq[byte]
    privateKey*: seq[byte]
  Envelope* = seq[byte]        # the thing you send

const
  PublicKeyBytes*   = KYBER_PUBLICKEYBYTES
  PrivateKeyBytes*  = KYBER_SECRETKEYBYTES
  EnvelopeBytes*    = KYBER_CIPHERTEXTBYTES
  SessionKeyBytes*  = KYBER_SSBYTES
  KeypairCoinBytes* = 2 * KYBER_SYMBYTES   # 64
  EncCoinBytes*     = KYBER_SYMBYTES       # 32


proc generateKeys*(coins: openArray[byte] = @[]): KeyPair =
  ## Make a new identity (public/private keys).
  ## Share publicKey, keep privateKey secret.
  result.publicKey  = newSeq[byte](PublicKeyBytes)
  result.privateKey = newSeq[byte](PrivateKeyBytes)
  if coins.len == 0:
    crypto_kem_keypair(result.publicKey, result.privateKey)
  else:
    if coins.len != KeypairCoinBytes: raise newException(ValueError, "generateKeys: coins must be 64 bytes")
    crypto_kem_keypair_derand(result.publicKey, result.privateKey, coins)


proc createEnvelope*(recipientPublicKey: openArray[byte],
                     coins: openArray[byte] = @[]): tuple[envelope: Envelope, sessionKey: seq[byte]] =
  ## Start a shared secret with someone’s public key.
  ## You send the returned envelope to them; you keep sessionKey locally.
  if recipientPublicKey.len != PublicKeyBytes: raise newException(ValueError, "createEnvelope: public key length")
  result.envelope   = newSeq[byte](EnvelopeBytes)
  result.sessionKey = newSeq[byte](SessionKeyBytes)
  if coins.len == 0:
    crypto_kem_enc(result.envelope, result.sessionKey, recipientPublicKey)
  else:
    if coins.len != EncCoinBytes: raise newException(ValueError, "createEnvelope: coins must be 32 bytes")
    crypto_kem_enc_derand(result.envelope, result.sessionKey, recipientPublicKey, coins)


proc openEnvelope*(myPrivateKey: openArray[byte], envelope: Envelope): seq[byte] =
  ## Finish the exchange: derive the same session key using your private key
  ## and the received envelope.
  if myPrivateKey.len != PrivateKeyBytes: raise newException(ValueError, "openEnvelope: private key length")
  if envelope.len != EnvelopeBytes:       raise newException(ValueError, "openEnvelope: envelope length")
  result = newSeq[byte](SessionKeyBytes)
  crypto_kem_dec(result, envelope, myPrivateKey)


when isMainModule:
  # --- Step 1: both sides generate identities and share public keys ---
  let alice = generateKeys()
  let bob   = generateKeys()
  # Alice sends alice.publicKey to Bob; Bob sends bob.publicKey to Alice.

  # --- Step 2: Bob creates an envelope with Alice’s public key ---
  let (envForAlice, bobSessionKey) = createEnvelope(alice.publicKey)
  # Bob sends `envForAlice` to Alice (over the network, email, etc.).

  # --- Step 3: Alice opens the envelope with her private key ---
  let aliceSessionKey = openEnvelope(alice.privateKey, envForAlice)

  # Both sides now share the same session key.
  doAssert bobSessionKey == aliceSessionKey
