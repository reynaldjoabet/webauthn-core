package webauthn.crypto

import webauthn.domain.*

import java.math.BigInteger
import java.security.{AlgorithmParameters, KeyFactory, PublicKey}
import java.security.spec.{
  ECGenParameterSpec,
  ECParameterSpec,
  ECPoint,
  ECPublicKeySpec,
  RSAPublicKeySpec,
  X509EncodedKeySpec
}
import scala.util.Try

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers
import org.bouncycastle.asn1.x509.{AlgorithmIdentifier, SubjectPublicKeyInfo}

/** Materialises a parsed [[CoseKey]] into a JCA [[java.security.PublicKey]] so
  * the signature verifier can use it. NIST curves and RSA use the platform
  * providers; Ed25519 (raw 32-byte key) and secp256k1 (absent from SunEC since
  * JDK 16) are built via BouncyCastle.
  */
object PublicKeys {

  def toJava(key: CoseKey): Either[String, PublicKey] =
    key match {
      case CoseKey.Ec2(_, curve, x, y) =>
        ec(curve, x.value.toArray, y.value.toArray)
      case CoseKey.Rsa(_, modulus, exp) =>
        rsa(modulus.value.toArray, exp.value.toArray)
      case CoseKey.Okp(_, curve, x) =>
        okp(curve, x.value.toArray)
    }

  private def ecStdName(curve: CoseEllipticCurve): Either[String, String] =
    curve match {
      case CoseEllipticCurve.P256      => Right("secp256r1")
      case CoseEllipticCurve.P384      => Right("secp384r1")
      case CoseEllipticCurve.P521      => Right("secp521r1")
      case CoseEllipticCurve.Secp256k1 => Right("secp256k1")
      case CoseEllipticCurve.Ed25519   => Left("Ed25519 is not an EC2 curve")
    }

  private def ec(
      curve: CoseEllipticCurve,
      x: Array[Byte],
      y: Array[Byte]
  ): Either[String, PublicKey] =
    for {
      std <- ecStdName(curve)
      key <- Try {
        val useBc = curve == CoseEllipticCurve.Secp256k1
        val params =
          if (useBc)
            AlgorithmParameters.getInstance("EC", Providers.bouncyCastle)
          else AlgorithmParameters.getInstance("EC")
        params.init(new ECGenParameterSpec(std))
        val spec = params.getParameterSpec(classOf[ECParameterSpec])
        val point = new ECPoint(new BigInteger(1, x), new BigInteger(1, y))
        val factory =
          if (useBc) KeyFactory.getInstance("EC", Providers.bouncyCastle)
          else KeyFactory.getInstance("EC")
        factory.generatePublic(new ECPublicKeySpec(point, spec))
      }.toEither.left.map(t => s"Invalid EC public key: ${t.getMessage}")
    } yield key

  private def rsa(
      modulus: Array[Byte],
      exponent: Array[Byte]
  ): Either[String, PublicKey] =
    Try {
      val spec =
        new RSAPublicKeySpec(
          new BigInteger(1, modulus),
          new BigInteger(1, exponent)
        )
      KeyFactory.getInstance("RSA").generatePublic(spec)
    }.toEither.left.map(t => s"Invalid RSA public key: ${t.getMessage}")

  private def okp(
      curve: CoseEllipticCurve,
      x: Array[Byte]
  ): Either[String, PublicKey] =
    curve match {
      case CoseEllipticCurve.Ed25519 =>
        Try {
          val algId = new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519)
          val spki = new SubjectPublicKeyInfo(algId, x)
          KeyFactory
            .getInstance("Ed25519", Providers.bouncyCastle)
            .generatePublic(new X509EncodedKeySpec(spki.getEncoded))
        }.toEither.left.map(t => s"Invalid Ed25519 public key: ${t.getMessage}")
      case other =>
        Left(s"Unsupported OKP curve: $other")
    }
}
