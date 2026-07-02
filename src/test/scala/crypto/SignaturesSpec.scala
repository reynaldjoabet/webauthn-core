package webauthn.crypto

import webauthn.domain.*

import java.math.BigInteger
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.{KeyPairGenerator, Signature}

class SignaturesSpec extends munit.FunSuite {

  /** Left-pads/normalises a BigInteger to an unsigned, fixed-width big-endian
    * byte vector (how COSE encodes EC coordinates).
    */
  private def fixedWidth(value: BigInteger, length: Int): Vector[Byte] = {
    val raw = value.toByteArray
    val unsigned =
      if (raw.length == length + 1 && raw(0) == 0) raw.tail
      else raw
    val out = Array.fill[Byte](length)(0)
    val src =
      if (unsigned.length > length) unsigned.takeRight(length) else unsigned
    System.arraycopy(src, 0, out, length - src.length, src.length)
    out.toVector
  }

  test("ES256 round-trip verifies and rejects tampered data") {
    val kpg = KeyPairGenerator.getInstance("EC")
    kpg.initialize(new ECGenParameterSpec("secp256r1"))
    val kp = kpg.generateKeyPair()
    val pub = kp.getPublic.asInstanceOf[ECPublicKey]

    val cose = CoseKey
      .ec2(
        CoseAlgorithm.ES256.identifier,
        CoseEllipticCurve.P256,
        fixedWidth(pub.getW.getAffineX, 32),
        fixedWidth(pub.getW.getAffineY, 32)
      )
      .fold(fail(_), identity)

    val data = "authenticatorData||clientDataHash".getBytes("UTF-8")
    val signer = Signature.getInstance("SHA256withECDSA")
    signer.initSign(kp.getPrivate)
    signer.update(data)
    val sig = signer.sign()

    assertEquals(Signatures.verify(cose, data, sig), Right(true))
    assertEquals(
      Signatures.verify(cose, "tampered".getBytes("UTF-8"), sig),
      Right(false)
    )
  }

  test(
    "ES256K round-trip verifies via BouncyCastle (secp256k1 absent from SunEC)"
  ) {
    val kpg = KeyPairGenerator.getInstance("EC", Providers.bouncyCastle)
    kpg.initialize(new ECGenParameterSpec("secp256k1"))
    val kp = kpg.generateKeyPair()
    val pub = kp.getPublic.asInstanceOf[ECPublicKey]

    val cose = CoseKey
      .ec2(
        CoseAlgorithm.ES256K.identifier,
        CoseEllipticCurve.Secp256k1,
        fixedWidth(pub.getW.getAffineX, 32),
        fixedWidth(pub.getW.getAffineY, 32)
      )
      .fold(fail(_), identity)

    val data = "es256k signed data".getBytes("UTF-8")
    val signer =
      Signature.getInstance("SHA256withECDSA", Providers.bouncyCastle)
    signer.initSign(kp.getPrivate)
    signer.update(data)
    val sig = signer.sign()

    assertEquals(Signatures.verify(cose, data, sig), Right(true))
    assertEquals(
      Signatures.verify(cose, "tampered".getBytes("UTF-8"), sig),
      Right(false)
    )
  }

  test("RS256 and PS256 round-trips verify") {
    val kp = KeyPairGenerator.getInstance("RSA").generateKeyPair()
    val pub = kp.getPublic.asInstanceOf[java.security.interfaces.RSAPublicKey]
    val modulus = pub.getModulus.toByteArray.dropWhile(_ == 0).toVector
    val exponent = pub.getPublicExponent.toByteArray.toVector

    def verifyWith(alg: CoseAlgorithm, jcaName: String): Unit = {
      val cose = CoseKey
        .rsa(alg.identifier, modulus, exponent)
        .fold(fail(_), identity)

      val data = s"$alg signed data".getBytes("UTF-8")
      val signer = Signature.getInstance(jcaName)
      if (jcaName == "RSASSA-PSS")
        signer.setParameter(
          new java.security.spec.PSSParameterSpec(
            "SHA-256",
            "MGF1",
            java.security.spec.MGF1ParameterSpec.SHA256,
            32,
            1
          )
        )
      signer.initSign(kp.getPrivate)
      signer.update(data)
      val sig = signer.sign()

      assertEquals(Signatures.verify(cose, data, sig), Right(true))
      assertEquals(
        Signatures.verify(cose, "tampered".getBytes("UTF-8"), sig),
        Right(false)
      )
    }

    verifyWith(CoseAlgorithm.RS256, "SHA256withRSA")
    verifyWith(CoseAlgorithm.PS256, "RSASSA-PSS")
  }

  test("Ed25519 round-trip verifies via BouncyCastle path") {
    val kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
    // The raw 32-byte public key is the BIT STRING tail of the X.509 SPKI.
    val raw = kp.getPublic.getEncoded.takeRight(32).toVector

    val cose = CoseKey
      .okpEd25519(CoseAlgorithm.EdDSA.identifier, raw)
      .fold(fail(_), identity)

    val data = "ed25519 signed data".getBytes("UTF-8")
    val signer = Signature.getInstance("Ed25519")
    signer.initSign(kp.getPrivate)
    signer.update(data)
    val sig = signer.sign()

    assertEquals(Signatures.verify(cose, data, sig), Right(true))
  }
}
