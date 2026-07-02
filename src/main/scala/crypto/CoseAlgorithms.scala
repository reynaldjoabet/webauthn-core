package webauthn.crypto

import webauthn.domain.CoseAlgorithm

/** Maps registered COSE algorithms to the JCA `Signature` algorithm names used
  * to verify WebAuthn assertion/attestation signatures.
  *
  * ECDSA (ES*) signatures arrive ASN.1/DER-encoded, which is what the JCA
  * `*withECDSA` verifiers expect. EdDSA signatures are raw. RS* are PKCS#1 v1.5
  * and PS* are RSASSA-PSS.
  */
object CoseAlgorithms {

  def jcaSignatureAlgorithm(alg: CoseAlgorithm): String =
    alg match {
      case CoseAlgorithm.ES256  => "SHA256withECDSA"
      case CoseAlgorithm.ES384  => "SHA384withECDSA"
      case CoseAlgorithm.ES512  => "SHA512withECDSA"
      case CoseAlgorithm.ES256K => "SHA256withECDSA"
      case CoseAlgorithm.RS256  => "SHA256withRSA"
      case CoseAlgorithm.RS384  => "SHA384withRSA"
      case CoseAlgorithm.RS512  => "SHA512withRSA"
      case CoseAlgorithm.RS1    => "SHA1withRSA"
      case CoseAlgorithm.PS256  => "SHA256withRSA/PSS"
      case CoseAlgorithm.PS384  => "SHA384withRSA/PSS"
      case CoseAlgorithm.PS512  => "SHA512withRSA/PSS"
      case CoseAlgorithm.EdDSA  => "Ed25519"
    }
}
