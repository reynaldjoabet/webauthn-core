package webauthn.domain

// ---------------------------------------------------------------------------
// COSE keys and algorithms (RFC 8152 / RFC 9052), as referenced by WebAuthn
// §5.8.5 (credentialPublicKey) and §6.5.6 (signature verification).
//
// The credentialPublicKey in attested credential data is a CBOR-encoded COSE
// key. To verify assertions/attestations a relying party must read the actual
// key material, not just hold the opaque bytes — these types model that.
// ---------------------------------------------------------------------------

/** COSE key type, the CBOR `kty` label (RFC 9053 §7). */
enum CoseKeyType derives CanEqual {
  case Okp // 1 — Octet Key Pair (Ed25519, etc.)
  case Ec2 // 2 — Double-coordinate elliptic curve
  case Rsa // 3 — RSA

  def label: Int =
    this match {
      case Okp => 1
      case Ec2 => 2
      case Rsa => 3
    }
}

object CoseKeyType {
  def fromLabel(label: Int): Option[CoseKeyType] =
    label match {
      case 1 => Some(Okp)
      case 2 => Some(Ec2)
      case 3 => Some(Rsa)
      case _ => None
    }
}

/** COSE elliptic curve, the CBOR `crv` label (IANA COSE Elliptic Curves). */
enum CoseEllipticCurve derives CanEqual {
  case P256 // 1  — NIST P-256 (secp256r1)
  case P384 // 2  — NIST P-384 (secp384r1)
  case P521 // 3  — NIST P-521 (secp521r1)
  case Ed25519 // 6  — Ed25519 for use with EdDSA
  case Secp256k1 // 8  — secp256k1

  def label: Int =
    this match {
      case P256      => 1
      case P384      => 2
      case P521      => 3
      case Ed25519   => 6
      case Secp256k1 => 8
    }
}

object CoseEllipticCurve {
  def fromLabel(label: Int): Option[CoseEllipticCurve] =
    label match {
      case 1 => Some(P256)
      case 2 => Some(P384)
      case 3 => Some(P521)
      case 6 => Some(Ed25519)
      case 8 => Some(Secp256k1)
      case _ => None
    }
}

/** Registered COSE algorithms relevant to WebAuthn (IANA COSE Algorithms).
  *
  * This is the closed set of algorithms a relying party can actually verify.
  * The wire value remains a raw [[CoseAlgorithmIdentifier]] so unknown
  * algorithms round-trip without loss; map to this enum when dispatching
  * verification logic.
  */
enum CoseAlgorithm derives CanEqual {
  case EdDSA
  case ES256, ES384, ES512, ES256K
  case RS256, RS384, RS512
  case PS256, PS384, PS512
  case RS1

  def identifier: CoseAlgorithmIdentifier =
    CoseAlgorithmIdentifier.applyUnsafe(this match {
      case EdDSA  => -8
      case ES256  => -7
      case ES384  => -35
      case ES512  => -36
      case ES256K => -47
      case RS256  => -257
      case RS384  => -258
      case RS512  => -259
      case PS256  => -37
      case PS384  => -38
      case PS512  => -39
      case RS1    => -65535
    })

  def keyType: CoseKeyType =
    this match {
      case EdDSA                          => CoseKeyType.Okp
      case ES256 | ES384 | ES512 | ES256K => CoseKeyType.Ec2
      case RS256 | RS384 | RS512 | PS256 | PS384 | PS512 | RS1 =>
        CoseKeyType.Rsa
    }
}

object CoseAlgorithm {
  def fromIdentifier(id: CoseAlgorithmIdentifier): Option[CoseAlgorithm] =
    values.find(_.identifier == id)
}

/** A parsed COSE public key (RFC 9053). Carries the structured key material a
  * relying party needs to verify a signature, alongside the algorithm the
  * authenticator declared for it. The raw CBOR encoding is retained separately
  * in [[AttestedCredentialData]] for storage / re-verification.
  */
enum CoseKey {

  /** Double-coordinate EC key (kty = EC2). `x`/`y` are the uncompressed,
    * unsigned, fixed-width coordinates per the curve.
    */
  case Ec2(
      alg: CoseAlgorithmIdentifier,
      curve: CoseEllipticCurve,
      x: NonEmptyBytes,
      y: NonEmptyBytes
  )

  /** Octet key pair (kty = OKP), e.g. Ed25519. `x` is the public key. */
  case Okp(
      alg: CoseAlgorithmIdentifier,
      curve: CoseEllipticCurve,
      x: NonEmptyBytes
  )

  /** RSA key (kty = RSA). `modulus` (n) and `exponent` (e) are big-endian,
    * unsigned.
    */
  case Rsa(
      alg: CoseAlgorithmIdentifier,
      modulus: NonEmptyBytes,
      exponent: NonEmptyBytes
  )

  /** The algorithm the authenticator bound to this key (the COSE `alg`),
    * regardless of key type.
    */
  def algorithm: CoseAlgorithmIdentifier =
    this match {
      case k: Ec2 => k.alg
      case k: Okp => k.alg
      case k: Rsa => k.alg
    }

  def keyType: CoseKeyType =
    this match {
      case _: Ec2 => CoseKeyType.Ec2
      case _: Okp => CoseKeyType.Okp
      case _: Rsa => CoseKeyType.Rsa
    }
}

object CoseKey {

  /** Size, in bytes, of a single field element / coordinate for a curve. */
  def coordinateSize(curve: CoseEllipticCurve): Int =
    curve match {
      case CoseEllipticCurve.P256 | CoseEllipticCurve.Secp256k1 => 32
      case CoseEllipticCurve.P384                               => 48
      case CoseEllipticCurve.P521                               => 66
      case CoseEllipticCurve.Ed25519                            => 32
    }

  /** Build an EC2 key, validating that each coordinate is non-empty and the
    * exact fixed width the curve requires.
    */
  def ec2(
      alg: CoseAlgorithmIdentifier,
      curve: CoseEllipticCurve,
      x: Vector[Byte],
      y: Vector[Byte]
  ): Either[String, CoseKey] =
    if (curve == CoseEllipticCurve.Ed25519)
      Left("Ed25519 is not a valid EC2 curve")
    else
      for {
        _ <- checkSize("EC2 x", curve, x)
        _ <- checkSize("EC2 y", curve, y)
        rx <- NonEmptyBytes.either(x)
        ry <- NonEmptyBytes.either(y)
      } yield Ec2(alg, curve, rx, ry)

  /** Build an Ed25519 OKP key, validating the 32-byte public key. */
  def okpEd25519(
      alg: CoseAlgorithmIdentifier,
      x: Vector[Byte]
  ): Either[String, CoseKey] =
    for {
      _ <- checkSize("OKP x", CoseEllipticCurve.Ed25519, x)
      rx <- NonEmptyBytes.either(x)
    } yield Okp(alg, CoseEllipticCurve.Ed25519, rx)

  /** Build an RSA key from big-endian, unsigned modulus and exponent. */
  def rsa(
      alg: CoseAlgorithmIdentifier,
      modulus: Vector[Byte],
      exponent: Vector[Byte]
  ): Either[String, CoseKey] =
    for {
      n <- NonEmptyBytes.either(modulus)
      e <- NonEmptyBytes.either(exponent)
    } yield Rsa(alg, n, e)

  private def checkSize(
      label: String,
      curve: CoseEllipticCurve,
      bytes: Vector[Byte]
  ): Either[String, Unit] = {
    val expected = coordinateSize(curve)
    if (bytes.length == expected) Right(())
    else Left(s"$label must be $expected bytes for $curve, got ${bytes.length}")
  }
}
