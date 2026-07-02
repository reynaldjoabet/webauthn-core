package webauthn.domain

class DomainModelSpec extends munit.FunSuite {

  test("closed wire enums round-trip through toString/fromString") {
    for (v <- PublicKeyCredentialType.values)
      assertEquals(PublicKeyCredentialType.fromString(v.toString), Some(v))
    for (v <- ClientDataType.values)
      assertEquals(ClientDataType.fromString(v.toString), Some(v))
    for (v <- AuthenticatorAttachment.values)
      assertEquals(AuthenticatorAttachment.fromString(v.toString), Some(v))
    for (v <- ResidentKeyRequirement.values)
      assertEquals(ResidentKeyRequirement.fromString(v.toString), Some(v))
    for (v <- UserVerificationRequirement.values)
      assertEquals(UserVerificationRequirement.fromString(v.toString), Some(v))
    for (v <- AttestationConveyancePreference.values)
      assertEquals(
        AttestationConveyancePreference.fromString(v.toString),
        Some(v)
      )
    for (v <- TokenBindingStatus.values)
      assertEquals(TokenBindingStatus.fromString(v.toString), Some(v))
    for (v <- LargeBlobSupport.values)
      assertEquals(LargeBlobSupport.fromString(v.toString), Some(v))
  }

  test("closed wire enums reject unknown values") {
    assertEquals(PublicKeyCredentialType.fromString("password"), None)
    assertEquals(ClientDataType.fromString("webauthn.payment"), None)
    assertEquals(UserVerificationRequirement.fromString("Required"), None)
  }

  test("open wire enums retain unknown values without loss") {
    val transports = List(
      AuthenticatorTransport.Usb,
      AuthenticatorTransport.Nfc,
      AuthenticatorTransport.Ble,
      AuthenticatorTransport.SmartCard,
      AuthenticatorTransport.Hybrid,
      AuthenticatorTransport.Internal
    )
    for (v <- transports)
      assertEquals(AuthenticatorTransport.fromString(v.toString), v)
    assertEquals(
      AuthenticatorTransport.fromString("quantum"),
      AuthenticatorTransport.Unknown("quantum")
    )

    val hints = List(
      PublicKeyCredentialHint.SecurityKey,
      PublicKeyCredentialHint.ClientDevice,
      PublicKeyCredentialHint.Hybrid
    )
    for (v <- hints)
      assertEquals(PublicKeyCredentialHint.fromString(v.toString), v)

    val formats = List(
      AttestationStatementFormat.None,
      AttestationStatementFormat.Packed,
      AttestationStatementFormat.Tpm,
      AttestationStatementFormat.AndroidKey,
      AttestationStatementFormat.AndroidSafetyNet,
      AttestationStatementFormat.FidoU2f,
      AttestationStatementFormat.Apple,
      AttestationStatementFormat.Compound
    )
    for (v <- formats)
      assertEquals(AttestationStatementFormat.fromString(v.toString), v)
    assertEquals(
      AttestationStatementFormat.fromString("acme-hsm"),
      AttestationStatementFormat.Unknown("acme-hsm")
    )
  }

  test("authenticator data flags round-trip through their flags octet") {
    // §6.1: UP=0x01, UV=0x04, BE=0x08, BS=0x10, AT=0x40, ED=0x80
    assertEquals(
      AuthenticatorDataFlags.fromByte(0x45.toByte),
      AuthenticatorDataFlags(
        userPresent = true,
        userVerified = true,
        backupEligible = false,
        backupState = false,
        attestedCredentialDataIncluded = true,
        extensionDataIncluded = false
      )
    )
    for (raw <- 0 to 255) {
      val flags = AuthenticatorDataFlags.fromByte(raw.toByte)
      // Reserved bits (0x02, 0x20) are dropped; the defined bits round-trip.
      assertEquals(flags.toByte, (raw & 0xdd).toByte)
    }
  }

  test("credProtect policy round-trips through its CTAP2 label") {
    for (v <- CredentialProtectionPolicy.values)
      assertEquals(CredentialProtectionPolicy.fromLabel(v.label), Some(v))
    assertEquals(CredentialProtectionPolicy.fromLabel(0), None)
    assertEquals(CredentialProtectionPolicy.fromLabel(4), None)
  }

  test("SignCount is bounded to uint32") {
    assert(SignCount.either(0L).isRight)
    assert(SignCount.either(4294967295L).isRight)
    assert(SignCount.either(-1L).isLeft)
    assert(SignCount.either(4294967296L).isLeft)
  }

  test("CoseKey.ec2 enforces fixed-width coordinates and rejects Ed25519") {
    val p256 = CoseEllipticCurve.P256
    val es256 = CoseAlgorithm.ES256.identifier
    val coord32 = Vector.fill[Byte](32)(1)

    assert(CoseKey.ec2(es256, p256, coord32, coord32).isRight)
    assert(CoseKey.ec2(es256, p256, coord32.tail, coord32).isLeft)
    assert(CoseKey.ec2(es256, p256, coord32, coord32 :+ 1.toByte).isLeft)
    assert(
      CoseKey
        .ec2(es256, CoseEllipticCurve.Ed25519, coord32, coord32)
        .isLeft
    )
  }

  test("CoseAlgorithm identifiers round-trip") {
    for (alg <- CoseAlgorithm.values)
      assertEquals(CoseAlgorithm.fromIdentifier(alg.identifier), Some(alg))
    assertEquals(
      CoseAlgorithm.fromIdentifier(CoseAlgorithmIdentifier.applyUnsafe(0)),
      None
    )
  }
}
