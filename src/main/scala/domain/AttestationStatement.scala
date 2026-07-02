package webauthn.domain

// ---------------------------------------------------------------------------
// Attestation statement formats (WebAuthn L2 §8).
//
// The attestationObject CBOR map is { fmt, authData, attStmt }. `attStmt` is a
// format-specific map; modelling it as a closed ADT (rather than opaque CBOR)
// lets the attestation verifier dispatch on the format and read exactly the
// members each format defines. `x5c` chains are DER certificates, leaf-first.
// ---------------------------------------------------------------------------

sealed trait AttestationStatement extends Product with Serializable {
  def format: AttestationStatementFormat
}

object AttestationStatement {

  /** §8.2 Packed. `x5c` is empty for self attestation (sig made with the
    * credential private key) and non-empty for Basic/AttCA attestation.
    */
  final case class Packed(
      alg: CoseAlgorithmIdentifier,
      sig: NonEmptyBytes,
      x5c: Vector[NonEmptyBytes]
  ) extends AttestationStatement {
    val format: AttestationStatementFormat = AttestationStatementFormat.Packed
  }

  /** §8.3 TPM. `certInfo` is a TPMS_ATTEST and `pubArea` a TPMT_PUBLIC. */
  final case class Tpm(
      ver: NonBlankText,
      alg: CoseAlgorithmIdentifier,
      sig: NonEmptyBytes,
      x5c: Vector[NonEmptyBytes],
      certInfo: NonEmptyBytes,
      pubArea: NonEmptyBytes
  ) extends AttestationStatement {
    val format: AttestationStatementFormat = AttestationStatementFormat.Tpm
  }

  /** §8.4 Android Key Attestation. */
  final case class AndroidKey(
      alg: CoseAlgorithmIdentifier,
      sig: NonEmptyBytes,
      x5c: Vector[NonEmptyBytes]
  ) extends AttestationStatement {
    val format: AttestationStatementFormat =
      AttestationStatementFormat.AndroidKey
  }

  /** §8.5 Android SafetyNet. `response` is the SafetyNet JWS, UTF-8 bytes. */
  final case class AndroidSafetyNet(
      ver: NonBlankText,
      response: NonEmptyBytes
  ) extends AttestationStatement {
    val format: AttestationStatementFormat =
      AttestationStatementFormat.AndroidSafetyNet
  }

  /** §8.6 FIDO U2F. `x5c` always holds exactly the attestation certificate. */
  final case class FidoU2f(
      sig: NonEmptyBytes,
      x5c: Vector[NonEmptyBytes]
  ) extends AttestationStatement {
    val format: AttestationStatementFormat = AttestationStatementFormat.FidoU2f
  }

  /** §8.8 Apple Anonymous. The nonce is verified from the leaf cert extension;
    * there is no signature member.
    */
  final case class Apple(
      x5c: Vector[NonEmptyBytes]
  ) extends AttestationStatement {
    val format: AttestationStatementFormat = AttestationStatementFormat.Apple
  }

  /** §8.7 None. Empty attStmt map. */
  case object None extends AttestationStatement {
    val format: AttestationStatementFormat = AttestationStatementFormat.None
  }

  /** An attestation format this library does not model; the raw attStmt CBOR is
    * retained so callers can still inspect or reject it.
    */
  final case class Unrecognized(
      format: AttestationStatementFormat,
      attStmt: NonEmptyBytes
  ) extends AttestationStatement
}
