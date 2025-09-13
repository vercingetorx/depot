# dilithium_api.nim
# Simple, friendly API for CRYSTALS-Dilithium (modes 2, 3, 5).

import src/[params, sign]

# ----- Sizes & names (depend on selected mode) -----

const
  PublicKeyBytes* = CRYPTO_PUBLICKEYBYTES
  SecretKeyBytes* = CRYPTO_SECRETKEYBYTES
  SignatureBytes* = CRYPTO_BYTES
  AlgorithmName* = when DILITHIUM_MODE == 2: "Dilithium2"
                  elif DILITHIUM_MODE == 3: "Dilithium3"
                  else: "Dilithium5"

type
  PublicKey* = array[PublicKeyBytes, byte]
  SecretKey* = array[SecretKeyBytes, byte]
  Signature* = array[SignatureBytes, byte]

# ----- Key generation -----

proc generateKeypair*(): (PublicKey, SecretKey) =
  ## Create a fresh Dilithium keypair.
  var pk: PublicKey
  var sk: SecretKey
  discard crypto_sign_keypair(pk, sk)
  return (pk, sk)

# ----- Detached signatures (keep message separate) -----

proc signDetached*(message: openArray[byte],
                   secretKey: SecretKey,
                   context: openArray[byte] = @[]): Signature =
  ## Produce a detached signature for `message` with optional `context`.
  var sig: Signature
  var sigLen: uint
  discard crypto_sign_signature(sig, sigLen, message, context, secretKey)
  return sig

proc verifyDetached*(signature: Signature,
                     message: openArray[byte],
                     publicKey: PublicKey,
                     context: openArray[byte] = @[]): bool =
  ## Check a detached signature for `message` (returns true if valid).
  result = (crypto_sign_verify(signature, message, context, publicKey) == 0)

# ----- Attached signatures (signature prepended to message) -----

proc signMessage*(message: openArray[byte],
                  secretKey: SecretKey,
                  context: openArray[byte] = @[]): seq[byte] =
  ## Return a signed message: `signature || message`.
  result = newSeq[byte](SignatureBytes + message.len)
  var smlen: uint
  discard crypto_sign(result, smlen, message, context, secretKey)
  result.setLen(smlen)

proc openSignedMessage*(signedMessage: openArray[byte],
                        publicKey: PublicKey,
                        context: openArray[byte] = @[]): (bool, seq[byte]) =
  ## Verify a signed message and return (ok, originalMessage).
  if signedMessage.len < SignatureBytes:
    return (false, @[])
  var m = newSeq[byte](signedMessage.len - SignatureBytes)
  var mlen: uint
  let ok = (crypto_sign_open(m, mlen, signedMessage, context, publicKey) == 0)
  if not ok: return (false, @[])
  m.setLen(mlen)
  return (true, m)

# ----- Convenience overloads for strings -----

proc signDetached*(message: string, secretKey: SecretKey,
    context: string = ""): Signature =
  signDetached(message.toOpenArrayByte(0, message.high), secretKey,
               context.toOpenArrayByte(0, max(-1, context.high)))

proc verifyDetached*(signature: Signature, message: string,
    publicKey: PublicKey, context: string = ""): bool =
  verifyDetached(signature,
                 message.toOpenArrayByte(0, message.high),
                 publicKey,
                 context.toOpenArrayByte(0, max(-1, context.high)))

proc signMessage*(message: string, secretKey: SecretKey,
    context: string = ""): seq[byte] =
  signMessage(message.toOpenArrayByte(0, message.high),
              secretKey,
              context.toOpenArrayByte(0, max(-1, context.high)))

proc openSignedMessage*(signedMessage: openArray[byte], publicKey: PublicKey,
    context: string): (bool, seq[byte]) =
  openSignedMessage(signedMessage,
                    publicKey,
                    context.toOpenArrayByte(0, max(-1, context.high)))


when isMainModule:
  # Helpers
  proc stringToBytes(s: string): seq[byte] =
    result = newSeq[byte](s.len)
    for i, ch in s: result[i] = byte(ch)

  proc bytesToString(b: openArray[byte]): string =
    result = newString(b.len)
    for i, v in b: result[i] = char(v)

  # ------------------------------------------------------------
  # 0) Create a key pair. Keep the secret key private. Share the public key.
  # ------------------------------------------------------------
  let (alicePublicKey, aliceSecretKey) = generateKeypair()

  # ============================================================
  # DETACHED SIGNATURES  (you send/store message and signature separately)
  # ============================================================

  # ------------------------------------------------------------
  # 1) Sign a TEXT message without a context label
  #    Verifier must pass the exact same message to check it.
  # ------------------------------------------------------------
  let textMessageNoContext = "hello Bob"
  let detachedSignatureNoContext = signDetached(textMessageNoContext, aliceSecretKey)
  let isValidDetachedNoContext = verifyDetached(detachedSignatureNoContext,
      textMessageNoContext, alicePublicKey)
  echo "[detached / text / no context] valid? ", isValidDetachedNoContext # true

  # ------------------------------------------------------------
  # 2) Sign a TEXT message WITH a context label
  #    A “context label” is just a short tag you choose (e.g. "payments/v1").
  #    If you use a label while signing, you must use the exact same label to verify.
  # ------------------------------------------------------------
  let contextLabel = "payments/v1"
  let invoiceText = "charge $20 to account #42"

  let detachedSignatureWithLabel = signDetached(invoiceText, aliceSecretKey, contextLabel)

  let isValidDetachedWithLabel = verifyDetached(detachedSignatureWithLabel,
      invoiceText, alicePublicKey, contextLabel)
  echo "[detached / text / with label] valid? ", isValidDetachedWithLabel # true

  # If the verifier uses a different label, verification fails:
  let isValidWrongLabel = verifyDetached(detachedSignatureWithLabel,
      invoiceText, alicePublicKey, "different-label")
  echo "[detached / text / wrong label] valid? ", isValidWrongLabel # false

  # ------------------------------------------------------------
  # 3) Sign BYTES (binary data) without a context label
  # ------------------------------------------------------------
  let fileChunk: seq[byte] = @[byte 0xDE, 0xAD, 0xBE, 0xEF]
  let detachedSignatureBytes = signDetached(fileChunk, aliceSecretKey)
  let isValidDetachedBytes = verifyDetached(detachedSignatureBytes, fileChunk, alicePublicKey)
  echo "[detached / bytes / no context] valid? ", isValidDetachedBytes # true

  # ------------------------------------------------------------
  # 4) Verifying with the WRONG public key fails
  # ------------------------------------------------------------
  let (otherPublicKey, _) = generateKeypair()
  let isValidWithWrongKey = verifyDetached(detachedSignatureNoContext,
      textMessageNoContext, otherPublicKey)
  echo "[detached / text / wrong public key] valid? ", isValidWithWrongKey # false

  # ============================================================
  # ATTACHED SIGNATURES  (you send/store one blob: signature || message)
  # ============================================================

  # ------------------------------------------------------------
  # 5) Sign a TEXT message WITH a context label (attached form)
  #    openSignedMessage() verifies AND gives you the original message back.
  # ------------------------------------------------------------
  let meetingNote = "meet at 12"
  let signedBlobWithLabel = signMessage(meetingNote, aliceSecretKey, contextLabel)

  let (isValidAttachedWithLabel, recoveredBytes1) = openSignedMessage(
      signedBlobWithLabel, alicePublicKey, contextLabel)

  let recoveredText1 = bytesToString(recoveredBytes1)
  echo "[attached / text / with label] valid? ", isValidAttachedWithLabel,
       "  recovered matches? ", (recoveredText1 == meetingNote) # true / true

  # If the signed blob is changed, verification fails:
  var tampered = signedBlobWithLabel
  if tampered.len > 0: tampered[0] = tampered[0] xor 1
  let (isValidAfterTamper, _) = openSignedMessage(tampered, alicePublicKey, contextLabel)
  echo "[attached / text / tampered] valid? ", isValidAfterTamper # false

  # ------------------------------------------------------------
  # 6) Sign BYTES without a context label (attached form)
  # ------------------------------------------------------------
  let dataBlock: seq[byte] = @[byte 1, 2, 3, 4, 5]
  let signedBlobNoLabel = signMessage(dataBlock, aliceSecretKey)       # no label
  let (isValidAttachedNoLabel, recoveredBytes2) = openSignedMessage(
      signedBlobNoLabel, alicePublicKey) # no label on verify
  echo "[attached / bytes / no context] valid? ", isValidAttachedNoLabel,
       "  recovered matches? ", (recoveredBytes2 == dataBlock) # true / true
