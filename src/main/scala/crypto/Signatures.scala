package webauthn.crypto

import webauthn.domain.*

import java.security.spec.{MGF1ParameterSpec, PSSParameterSpec}
import java.security.{Signature => JcaSignature}
import scala.util.Try

/** Verifies WebAuthn signatures (§7.2 step 20, §7.1 step 21) against a parsed
  * COSE credential public key.
  *
  * `signedData` is the bytes the authenticator signed — for an assertion this
  * is `authenticatorData || SHA-256(clientDataJSON)`; for packed attestation it
  * is `authenticatorData || clientDataHash`. The caller assembles it; this
  * helper only performs the cryptographic check.
  */
object Signatures {

  def verify(
      key: CoseKey,
      signedData: Array[Byte],
      signature: Array[Byte]
  ): Either[String, Boolean] =
    for {
      alg <- CoseAlgorithm
        .fromIdentifier(key.algorithm)
        .toRight(s"Unsupported COSE algorithm: ${key.algorithm}")
      pub <- PublicKeys.toJava(key)
      ok <- Try {
        val sig = instance(alg)
        sig.initVerify(pub)
        sig.update(signedData)
        sig.verify(signature)
      }.toEither.left.map(t => s"Signature verification error: ${t.getMessage}")
    } yield ok

  /** Build and parameterise the JCA verifier for an algorithm. EdDSA and ES256K
    * run on BouncyCastle (matching the keys built by [[PublicKeys]]; SunEC has
    * no secp256k1 since JDK 16); RSASSA-PSS is configured with MGF1 and a salt
    * length equal to the digest length.
    */
  private def instance(alg: CoseAlgorithm): JcaSignature =
    alg match {
      case CoseAlgorithm.EdDSA =>
        JcaSignature.getInstance("Ed25519", Providers.bouncyCastle)

      case CoseAlgorithm.ES256K =>
        JcaSignature.getInstance("SHA256withECDSA", Providers.bouncyCastle)

      case CoseAlgorithm.PS256 => pss("SHA-256", 32)
      case CoseAlgorithm.PS384 => pss("SHA-384", 48)
      case CoseAlgorithm.PS512 => pss("SHA-512", 64)

      case other =>
        JcaSignature.getInstance(CoseAlgorithms.jcaSignatureAlgorithm(other))
    }

  private def pss(hash: String, saltLength: Int): JcaSignature = {
    val sig = JcaSignature.getInstance("RSASSA-PSS")
    sig.setParameter(
      new PSSParameterSpec(
        hash,
        "MGF1",
        new MGF1ParameterSpec(hash),
        saltLength,
        1
      )
    )
    sig
  }
}
