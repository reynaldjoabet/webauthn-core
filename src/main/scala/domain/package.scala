package webauthn.domain

import io.github.iltotore.iron.*
import io.github.iltotore.iron.constraint.any.*
import io.github.iltotore.iron.constraint.collection.*
import io.github.iltotore.iron.constraint.numeric.*
import io.github.iltotore.iron.constraint.string.*
import io.circe.Json
import java.time.Instant
import java.util.UUID

// ---------------------------------------------------------------------------
// Generic refined primitives
// ---------------------------------------------------------------------------

type NonBlankText = NonBlankText.T
object NonBlankText extends RefinedType[String, Not[Blank]]

type Base64UrlNoPadding = Base64UrlNoPadding.T
object Base64UrlNoPadding extends RefinedType[String, Match["^[A-Za-z0-9_-]*$"]]

type NonEmptyBase64UrlNoPadding = NonEmptyBase64UrlNoPadding.T
object NonEmptyBase64UrlNoPadding
    extends RefinedType[String, Match["^[A-Za-z0-9_-]+$"]]

type NonEmptyBytes = NonEmptyBytes.T
object NonEmptyBytes extends RefinedType[Vector[Byte], MinLength[1]]

type ChallengeBytes = ChallengeBytes.T
object ChallengeBytes extends RefinedType[Vector[Byte], MinLength[16]]

type UserHandle = UserHandle.T
object UserHandle
    extends RefinedType[Vector[Byte], MinLength[1] & MaxLength[64]]

type CredentialId = CredentialId.T
object CredentialId
    extends RefinedType[Vector[Byte], MinLength[1] & MaxLength[1023]]

type Aaguid = Aaguid.T
object Aaguid extends RefinedType[Vector[Byte], FixedLength[16]]

type RpIdHash = RpIdHash.T
object RpIdHash extends RefinedType[Vector[Byte], FixedLength[32]]

/** Signature counter, a 32-bit unsigned integer (§6.1.1). */
type SignCount = SignCount.T
object SignCount extends RefinedType[Long, Interval.Closed[0L, 4294967295L]]

type TimeoutMillis = TimeoutMillis.T
object TimeoutMillis extends RefinedType[Long, Positive]

type CoseAlgorithmIdentifier = CoseAlgorithmIdentifier.T
object CoseAlgorithmIdentifier extends RefinedType[Int, Pure] {
  val EdDSA: CoseAlgorithmIdentifier = applyUnsafe(-8)
  val ES256: CoseAlgorithmIdentifier = applyUnsafe(-7)
  val RS256: CoseAlgorithmIdentifier = applyUnsafe(-257)
}

// ---------------------------------------------------------------------------
// Relying Party and user account domain
// ---------------------------------------------------------------------------

type RelyingPartyId = RelyingPartyId.T

/** WebAuthn RP ID.
  *
  * Do not over-validate this with a regex. Actual RP ID validity depends on
  * origin, effective domain, registrable domain suffix, and browser rules.
  */
object RelyingPartyId extends RefinedType[String, Not[Blank]]

type RelyingPartyName = RelyingPartyName.T
object RelyingPartyName extends RefinedType[String, Not[Blank]]

type Origin = Origin.T
object Origin extends RefinedType[String, Not[Blank]]

type UserAccountId = UserAccountId.T
object UserAccountId extends RefinedType[UUID, Pure]

type UserName = UserName.T
object UserName extends RefinedType[String, Not[Blank]]

/** Human-displayable name. WebAuthn allows an empty displayName if no suitable
  * human-palatable name is available, so keep this as String.
  */
type UserDisplayName = String

final case class RelyingParty(
    id: RelyingPartyId,
    name: RelyingPartyName,
    allowedOrigins: Set[Origin]
)

final case class WebAuthnUser(
    accountId: UserAccountId,
    handle: UserHandle,
    name: UserName,
    displayName: UserDisplayName
)

// ---------------------------------------------------------------------------
// WebAuthn enums / DOMString-like values
// ---------------------------------------------------------------------------

enum PublicKeyCredentialType derives CanEqual {
  case PublicKey

  override def toString: String =
    this match {
      case PublicKey => "public-key"
    }
}

object PublicKeyCredentialType {
  def fromString(value: String): Option[PublicKeyCredentialType] =
    value match {
      case "public-key" => Some(PublicKey)
      case _            => Option.empty
    }
}

enum ClientDataType derives CanEqual {
  case Create
  case Get

  override def toString: String =
    this match {
      case Create => "webauthn.create"
      case Get    => "webauthn.get"
    }
}

object ClientDataType {
  def fromString(value: String): Option[ClientDataType] =
    value match {
      case "webauthn.create" => Some(Create)
      case "webauthn.get"    => Some(Get)
      case _                 => Option.empty
    }
}

enum AuthenticatorTransport derives CanEqual {
  case Usb
  case Nfc
  case Ble
  case SmartCard // WebAuthn L3
  case Hybrid // WebAuthn L3 (replaced L1 "cable")
  case Internal
  case Unknown(value: String)

  override def toString: String =
    this match {
      case Usb            => "usb"
      case Nfc            => "nfc"
      case Ble            => "ble"
      case SmartCard      => "smart-card"
      case Hybrid         => "hybrid"
      case Internal       => "internal"
      case Unknown(value) => value.toLowerCase()
    }
}

object AuthenticatorTransport {

  /** Total: WebAuthn asks clients and RPs to tolerate transports minted after
    * they shipped, so unrecognised values are retained, not rejected.
    */
  def fromString(value: String): AuthenticatorTransport =
    value match {
      case "usb"        => Usb
      case "nfc"        => Nfc
      case "ble"        => Ble
      case "smart-card" => SmartCard
      case "hybrid"     => Hybrid
      case "internal"   => Internal
      case other        => Unknown(other)
    }
}

enum AuthenticatorAttachment derives CanEqual {
  case Platform
  case CrossPlatform

  override def toString: String =
    this match {
      case Platform      => "platform"
      case CrossPlatform => "cross-platform"
    }
}

object AuthenticatorAttachment {
  def fromString(value: String): Option[AuthenticatorAttachment] =
    value match {
      case "platform"       => Some(Platform)
      case "cross-platform" => Some(CrossPlatform)
      case _                => Option.empty
    }
}

enum ResidentKeyRequirement derives CanEqual {
  case Discouraged
  case Preferred
  case Required

  override def toString: String =
    this match {
      case Discouraged => "discouraged"
      case Preferred   => "preferred"
      case Required    => "required"
    }
}

object ResidentKeyRequirement {
  def fromString(value: String): Option[ResidentKeyRequirement] =
    value match {
      case "discouraged" => Some(Discouraged)
      case "preferred"   => Some(Preferred)
      case "required"    => Some(Required)
      case _             => Option.empty
    }
}

enum UserVerificationRequirement derives CanEqual {
  case Required
  case Preferred
  case Discouraged

  override def toString: String =
    this match {
      case Required    => "required"
      case Preferred   => "preferred"
      case Discouraged => "discouraged"
    }
}

object UserVerificationRequirement {
  def fromString(value: String): Option[UserVerificationRequirement] =
    value match {
      case "required"    => Some(Required)
      case "preferred"   => Some(Preferred)
      case "discouraged" => Some(Discouraged)
      case _             => Option.empty
    }
}

enum AttestationConveyancePreference derives CanEqual {
  case None
  case Indirect
  case Direct
  case Enterprise

  override def toString: String =
    this match {
      case None       => "none"
      case Indirect   => "indirect"
      case Direct     => "direct"
      case Enterprise => "enterprise"
    }
}

object AttestationConveyancePreference {
  def fromString(value: String): Option[AttestationConveyancePreference] =
    value match {
      case "none"       => Some(AttestationConveyancePreference.None)
      case "indirect"   => Some(Indirect)
      case "direct"     => Some(Direct)
      case "enterprise" => Some(Enterprise)
      case _            => Option.empty
    }
}

enum PublicKeyCredentialHint derives CanEqual {
  case SecurityKey
  case ClientDevice
  case Hybrid
  case Unknown(value: String)

  override def toString: String =
    this match {
      case SecurityKey    => "security-key"
      case ClientDevice   => "client-device"
      case Hybrid         => "hybrid"
      case Unknown(value) => value.toLowerCase()
    }
}

object PublicKeyCredentialHint {

  /** Total: hints are advisory, so unrecognised values are retained. */
  def fromString(value: String): PublicKeyCredentialHint =
    value match {
      case "security-key"  => SecurityKey
      case "client-device" => ClientDevice
      case "hybrid"        => Hybrid
      case other           => Unknown(other)
    }
}

enum AttestationStatementFormat derives CanEqual {
  case None
  case Packed
  case Tpm
  case AndroidKey
  case AndroidSafetyNet
  case FidoU2f
  case Apple
  case Compound // WebAuthn L3
  case Unknown(value: String)

  override def toString: String =
    this match {
      case None             => "none"
      case Packed           => "packed"
      case Tpm              => "tpm"
      case AndroidKey       => "android-key"
      case AndroidSafetyNet => "android-safetynet"
      case FidoU2f          => "fido-u2f"
      case Apple            => "apple"
      case Compound         => "compound"
      case Unknown(value)   => value.toLowerCase()
    }
}

object AttestationStatementFormat {

  /** Total: an attestation object may carry a format this library does not
    * model; it is retained as [[Unknown]] and dispatched to
    * [[AttestationStatement.Unrecognized]] rather than rejected at parse time.
    */
  def fromString(value: String): AttestationStatementFormat =
    value match {
      case "none"              => AttestationStatementFormat.None
      case "packed"            => Packed
      case "tpm"               => Tpm
      case "android-key"       => AndroidKey
      case "android-safetynet" => AndroidSafetyNet
      case "fido-u2f"          => FidoU2f
      case "apple"             => Apple
      case "compound"          => Compound
      case other               => Unknown(other)
    }
}

enum TokenBindingStatus derives CanEqual {
  case Present
  case Supported

  override def toString: String =
    this match {
      case Present   => "present"
      case Supported => "supported"
    }
}

object TokenBindingStatus {
  def fromString(value: String): Option[TokenBindingStatus] =
    value match {
      case "present"   => Some(Present)
      case "supported" => Some(Supported)
      case _           => Option.empty
    }
}

// ---------------------------------------------------------------------------
// Credential generation options: server -> browser
// ---------------------------------------------------------------------------

final case class PublicKeyCredentialRpEntity(
    id: Option[RelyingPartyId],
    name: RelyingPartyName
)

final case class PublicKeyCredentialUserEntity(
    id: UserHandle,
    name: UserName,
    displayName: UserDisplayName
)

final case class PublicKeyCredentialParameters(
    credentialType: PublicKeyCredentialType,
    alg: CoseAlgorithmIdentifier
)

object PublicKeyCredentialParameters {
  val recommended: Vector[PublicKeyCredentialParameters] =
    Vector(
      PublicKeyCredentialParameters(
        credentialType = PublicKeyCredentialType.PublicKey,
        alg = CoseAlgorithmIdentifier.EdDSA
      ),
      PublicKeyCredentialParameters(
        credentialType = PublicKeyCredentialType.PublicKey,
        alg = CoseAlgorithmIdentifier.ES256
      ),
      PublicKeyCredentialParameters(
        credentialType = PublicKeyCredentialType.PublicKey,
        alg = CoseAlgorithmIdentifier.RS256
      )
    )
}

final case class PublicKeyCredentialDescriptor(
    credentialType: PublicKeyCredentialType,
    id: CredentialId,
    transports: Set[AuthenticatorTransport]
)

final case class AuthenticatorSelectionCriteria(
    authenticatorAttachment: Option[AuthenticatorAttachment],
    residentKey: Option[ResidentKeyRequirement],
    requireResidentKey: Boolean,
    userVerification: UserVerificationRequirement
)

object AuthenticatorSelectionCriteria {
  val passkeyPreferred: AuthenticatorSelectionCriteria =
    AuthenticatorSelectionCriteria(
      authenticatorAttachment = None,
      residentKey = Some(ResidentKeyRequirement.Preferred),
      requireResidentKey = false,
      userVerification = UserVerificationRequirement.Preferred
    )

  val platformPasskeyRequired: AuthenticatorSelectionCriteria =
    AuthenticatorSelectionCriteria(
      authenticatorAttachment = Some(AuthenticatorAttachment.Platform),
      residentKey = Some(ResidentKeyRequirement.Required),
      requireResidentKey = true,
      userVerification = UserVerificationRequirement.Required
    )
}

final case class PublicKeyCredentialCreationOptions(
    rp: PublicKeyCredentialRpEntity,
    user: PublicKeyCredentialUserEntity,
    challenge: ChallengeBytes,
    pubKeyCredParams: Vector[PublicKeyCredentialParameters],
    timeout: Option[TimeoutMillis],
    excludeCredentials: Vector[PublicKeyCredentialDescriptor],
    authenticatorSelection: Option[AuthenticatorSelectionCriteria],
    hints: Vector[PublicKeyCredentialHint], // WebAuthn L3 extension
    attestation: AttestationConveyancePreference,
    attestationFormats: Vector[
      AttestationStatementFormat
    ], // WebAuthn L3 extension
    extensions: Option[ClientExtensionInputs]
)

// ---------------------------------------------------------------------------
// Assertion generation options: server -> browser
// ---------------------------------------------------------------------------

final case class PublicKeyCredentialRequestOptions(
    challenge: ChallengeBytes,
    timeout: Option[TimeoutMillis],
    rpId: Option[RelyingPartyId],
    allowCredentials: Vector[PublicKeyCredentialDescriptor],
    userVerification: UserVerificationRequirement,
    hints: Vector[PublicKeyCredentialHint], // WebAuthn L3 extension
    extensions: Option[ClientExtensionInputs]
)

// ---------------------------------------------------------------------------
// Browser response domain: browser -> server
// ---------------------------------------------------------------------------

final case class CollectedClientData(
    typ: ClientDataType,
    challenge: Base64UrlNoPadding,
    origin: Origin,
    crossOrigin: Option[Boolean],
    topOrigin: Option[Origin], // WebAuthn L3 extension
    tokenBinding: Option[TokenBinding] // WebAuthn L1 legacy; removed in L2
)

final case class TokenBinding(
    status: TokenBindingStatus,
    id: Option[NonBlankText]
)

/** Raw PublicKeyCredential object received during registration.
  *
  * The values here are still raw client output. Verification must parse
  * clientDataJSON, attestationObject, authenticatorData, and the public key.
  */
final case class RegistrationCredentialResponse(
    id: NonEmptyBase64UrlNoPadding,
    rawId: CredentialId,
    credentialType: PublicKeyCredentialType,
    response: AuthenticatorAttestationResponse,
    authenticatorAttachment: Option[AuthenticatorAttachment],
    clientExtensionResults: ClientExtensionOutputs
)

final case class AuthenticatorAttestationResponse(
    clientDataJson: NonEmptyBytes,
    attestationObject: NonEmptyBytes,
    transports: Set[AuthenticatorTransport],
    authenticatorData: Option[NonEmptyBytes],
    publicKey: Option[NonEmptyBytes],
    publicKeyAlgorithm: Option[CoseAlgorithmIdentifier]
)

/** Raw PublicKeyCredential object received during authentication.
  */
final case class AuthenticationCredentialResponse(
    id: NonEmptyBase64UrlNoPadding,
    rawId: CredentialId,
    credentialType: PublicKeyCredentialType,
    response: AuthenticatorAssertionResponse,
    authenticatorAttachment: Option[AuthenticatorAttachment],
    clientExtensionResults: ClientExtensionOutputs
)

final case class AuthenticatorAssertionResponse(
    clientDataJson: NonEmptyBytes,
    authenticatorData: NonEmptyBytes,
    signature: NonEmptyBytes,
    userHandle: Option[UserHandle]
)

// ---------------------------------------------------------------------------
// Parsed authenticator data
// ---------------------------------------------------------------------------

final case class AuthenticatorData(
    rpIdHash: RpIdHash,
    flags: AuthenticatorDataFlags,
    signCount: SignCount,
    attestedCredentialData: Option[AttestedCredentialData],
    extensions: Option[AuthenticatorExtensionOutputs]
)

final case class AuthenticatorDataFlags(
    userPresent: Boolean,
    userVerified: Boolean,
    backupEligible: Boolean,
    backupState: Boolean,
    attestedCredentialDataIncluded: Boolean,
    extensionDataIncluded: Boolean
) {
  def toByte: Byte =
    ((if (userPresent) AuthenticatorDataFlags.UP else 0)
      | (if (userVerified) AuthenticatorDataFlags.UV else 0)
      | (if (backupEligible) AuthenticatorDataFlags.BE else 0)
      | (if (backupState) AuthenticatorDataFlags.BS else 0)
      | (if (attestedCredentialDataIncluded) AuthenticatorDataFlags.AT else 0)
      | (if (extensionDataIncluded) AuthenticatorDataFlags.ED else 0)).toByte
}

object AuthenticatorDataFlags {

  // Bit masks for the authenticator data flags octet (§6.1, Figure 5).
  private val UP = 0x01 // user present
  private val UV = 0x04 // user verified
  private val BE = 0x08 // backup eligible
  private val BS = 0x10 // backup state
  private val AT = 0x40 // attested credential data included
  private val ED = 0x80 // extension data included

  def fromByte(flags: Byte): AuthenticatorDataFlags =
    AuthenticatorDataFlags(
      userPresent = (flags & UP) != 0,
      userVerified = (flags & UV) != 0,
      backupEligible = (flags & BE) != 0,
      backupState = (flags & BS) != 0,
      attestedCredentialDataIncluded = (flags & AT) != 0,
      extensionDataIncluded = (flags & ED) != 0
    )
}

final case class AttestedCredentialData(
    aaguid: Aaguid,
    credentialId: CredentialId,
    /** The parsed COSE public key. */
    credentialPublicKey: CoseKey,
    /** The exact COSE-encoded bytes as they appeared in the authenticator data,
      * retained verbatim for storage and signature re-verification.
      */
    credentialPublicKeyBytes: NonEmptyBytes
)

enum CredentialPublicKeyEncoding {
  case CoseKey
  case SubjectPublicKeyInfo
}

final case class CredentialPublicKey(
    encoding: CredentialPublicKeyEncoding,
    alg: CoseAlgorithmIdentifier,
    bytes: NonEmptyBytes
)

/** A decoded attestationObject: { fmt, authData, attStmt }. The format lives on
  * [[AttestationStatement.format]], which the verifier must confirm matches the
  * `fmt` key read off the wire.
  *
  * `rawAuthData` is the exact authData byte string from the CBOR map: every
  * attestation signature (§8) is computed over `authData || clientDataHash`, so
  * the verbatim bytes must be retained alongside the parsed view.
  */
final case class ParsedAttestationObject(
    authData: AuthenticatorData,
    rawAuthData: NonEmptyBytes,
    attStmt: AttestationStatement
)

// ---------------------------------------------------------------------------
// Stored credential record
// ---------------------------------------------------------------------------

final case class CredentialRecord(
    userAccountId: UserAccountId,
    userHandle: UserHandle,
    rpId: RelyingPartyId,
    credentialType: PublicKeyCredentialType,
    credentialId: CredentialId,
    publicKey: CredentialPublicKey,
    signCount: SignCount,
    uvInitialized: Boolean,
    transports: Set[AuthenticatorTransport],
    backupEligible: Boolean,
    backupState: Boolean,
    attestationObject: Option[NonEmptyBytes],
    attestationClientDataJson: Option[NonEmptyBytes],
    createdAt: Instant,
    lastUsedAt: Option[Instant],
    nickname: Option[NonBlankText]
)

object CredentialRecord {
  def descriptor(record: CredentialRecord): PublicKeyCredentialDescriptor =
    PublicKeyCredentialDescriptor(
      credentialType = record.credentialType,
      id = record.credentialId,
      transports = record.transports
    )
}

// ---------------------------------------------------------------------------
// Ceremony/session state
// ---------------------------------------------------------------------------

type CeremonyId = CeremonyId.T
object CeremonyId extends RefinedType[UUID, Pure]

enum CeremonyKind {
  case Registration
  case Authentication
}

final case class RegistrationCeremony(
    id: CeremonyId,
    rpId: RelyingPartyId,
    origin: Origin,
    userAccountId: UserAccountId,
    userHandle: UserHandle,
    challenge: ChallengeBytes,
    requestedUserVerification: UserVerificationRequirement,
    attestation: AttestationConveyancePreference,
    createdAt: Instant,
    expiresAt: Instant
)

final case class AuthenticationCeremony(
    id: CeremonyId,
    rpId: RelyingPartyId,
    origin: Origin,
    userAccountId: Option[UserAccountId],
    challenge: ChallengeBytes,
    requestedUserVerification: UserVerificationRequirement,
    allowedCredentialIds: Set[CredentialId],
    createdAt: Instant,
    expiresAt: Instant
)

// ---------------------------------------------------------------------------
// Verification outputs
// ---------------------------------------------------------------------------

final case class VerifiedRegistration(
    ceremony: RegistrationCeremony,
    credentialRecord: CredentialRecord,
    attestation: VerifiedAttestation
)

enum AttestationTrust {
  case None
  case Self
  case Basic
  case AttestationCa
  case AnonymizationCa
  case Uncertain
}

final case class VerifiedAttestation(
    fmt: AttestationStatementFormat,
    trust: AttestationTrust,
    aaguid: Option[Aaguid]
)

final case class VerifiedAuthentication(
    ceremony: AuthenticationCeremony,
    userAccountId: UserAccountId,
    credentialId: CredentialId,
    newSignCount: SignCount,
    userPresent: Boolean,
    userVerified: Boolean,
    backupEligible: Boolean,
    backupState: Boolean,
    authenticatedAt: Instant
)

// ---------------------------------------------------------------------------
// Domain errors
// ---------------------------------------------------------------------------

sealed trait WebAuthnError extends Product with Serializable {
  def message: String
}

object WebAuthnError {

  final case class InvalidBase64Url(value: String, reason: String)
      extends WebAuthnError {
    override val message: String =
      s"Invalid base64url value: $reason"
  }

  final case class InvalidClientData(reason: String) extends WebAuthnError {
    override val message: String =
      s"Invalid WebAuthn clientDataJSON: $reason"
  }

  final case class InvalidAuthenticatorData(reason: String)
      extends WebAuthnError {
    override val message: String =
      s"Invalid WebAuthn authenticatorData: $reason"
  }

  final case class InvalidAttestation(reason: String) extends WebAuthnError {
    override val message: String =
      s"Invalid WebAuthn attestation: $reason"
  }

  final case class InvalidAssertion(reason: String) extends WebAuthnError {
    override val message: String =
      s"Invalid WebAuthn assertion: $reason"
  }

  final case class ChallengeMismatch(expected: ChallengeBytes)
      extends WebAuthnError {
    override val message: String =
      "Returned WebAuthn challenge does not match the ceremony challenge"
  }

  final case class OriginNotAllowed(origin: Origin) extends WebAuthnError {
    override val message: String =
      s"Origin is not allowed for this relying party: $origin"
  }

  final case class RelyingPartyIdMismatch(expected: RelyingPartyId)
      extends WebAuthnError {
    override val message: String =
      s"Authenticator data does not match RP ID: $expected"
  }

  final case class CredentialAlreadyRegistered(id: CredentialId)
      extends WebAuthnError {
    override val message: String =
      "Credential is already registered"
  }

  final case class CredentialNotFound(id: CredentialId) extends WebAuthnError {
    override val message: String =
      "Credential was not found"
  }

  final case class CeremonyNotFound(id: CeremonyId) extends WebAuthnError {
    override val message: String =
      "WebAuthn ceremony was not found"
  }

  final case class CeremonyExpired(id: CeremonyId) extends WebAuthnError {
    override val message: String =
      "WebAuthn ceremony has expired"
  }

  final case class CredentialTypeMismatch(received: String)
      extends WebAuthnError {
    override val message: String =
      s"""Credential type must be "public-key", got: $received"""
  }

  case object UserPresenceRequired extends WebAuthnError {
    override val message: String =
      "The UP (user present) flag was not set in authenticator data"
  }

  case object UserVerificationRequired extends WebAuthnError {
    override val message: String =
      "User verification was required but the UV flag was not set"
  }

  final case class UserHandleMismatch(expected: UserHandle)
      extends WebAuthnError {
    override val message: String =
      "Returned user handle does not identify the user who owns the credential"
  }

  final case class UnsupportedAlgorithm(alg: CoseAlgorithmIdentifier)
      extends WebAuthnError {
    override val message: String =
      s"COSE algorithm is not supported: $alg"
  }

  case object InvalidSignature extends WebAuthnError {
    override val message: String =
      "WebAuthn signature verification failed"
  }

  final case class SignatureCounterRollback(
      stored: SignCount,
      received: SignCount
  ) extends WebAuthnError {
    override val message: String =
      "Received signature counter is lower than or equal to the stored counter"
  }
}

// ---------------------------------------------------------------------------
// Server -> browser JSON DTOs. Keep these boring and close to the browser API.
// Derive jsoniter/zio-json codecs in this layer, not in the domain layer.
// ---------------------------------------------------------------------------

final case class RegistrationStartResponseJson(
    ceremonyId: String,
    publicKey: PublicKeyCredentialCreationOptionsJson
)

final case class AuthenticationStartResponseJson(
    ceremonyId: String,
    publicKey: PublicKeyCredentialRequestOptionsJson
)

final case class PublicKeyCredentialCreationOptionsJson(
    rp: PublicKeyCredentialRpEntityJson,
    user: PublicKeyCredentialUserEntityJson,
    challenge: String,
    pubKeyCredParams: Vector[PublicKeyCredentialParametersJson],
    timeout: Option[Long],
    excludeCredentials: Vector[PublicKeyCredentialDescriptorJson],
    authenticatorSelection: AuthenticatorSelectionCriteriaJson,
    hints: Vector[String],
    attestation: String
)

final case class PublicKeyCredentialRequestOptionsJson(
    challenge: String,
    timeout: Option[Long],
    rpId: String,
    allowCredentials: Vector[PublicKeyCredentialDescriptorJson],
    userVerification: String,
    hints: Vector[String]
)

final case class PublicKeyCredentialRpEntityJson(
    id: String,
    name: String
)

final case class PublicKeyCredentialUserEntityJson(
    id: String,
    name: String,
    displayName: String
)

final case class PublicKeyCredentialParametersJson(
    `type`: String,
    alg: Int
)

final case class PublicKeyCredentialDescriptorJson(
    `type`: String,
    id: String,
    transports: Vector[String]
)

final case class AuthenticatorSelectionCriteriaJson(
    authenticatorAttachment: Option[String],
    residentKey: String,
    requireResidentKey: Boolean,
    userVerification: String
)

// ---------------------------------------------------------------------------
// Browser -> server JSON DTOs. These are untrusted until verified.
// ---------------------------------------------------------------------------

final case class RegistrationFinishRequestJson(
    ceremonyId: String,
    credential: RegistrationResponseJSON
)

final case class AuthenticationFinishRequestJson(
    ceremonyId: String,
    credential: AuthenticationResponseJSON
)

final case class RegistrationResponseJSON(
    id: String,
    rawId: String,
    response: AuthenticatorAttestationResponseJSON,
    authenticatorAttachment: Option[String],
    clientExtensionResults: Map[String, Json],
    `type`: String
)

final case class AuthenticatorAttestationResponseJSON(
    clientDataJSON: String,
    authenticatorData: String,
    transports: Vector[String],
    publicKey: Option[String],
    publicKeyAlgorithm: Int,
    attestationObject: String
)

final case class AuthenticationResponseJSON(
    id: String,
    rawId: String,
    response: AuthenticatorAssertionResponseJSON,
    authenticatorAttachment: Option[String],
    clientExtensionResults: Map[String, Json],
    `type`: String
)

final case class AuthenticatorAssertionResponseJSON(
    clientDataJSON: String,
    authenticatorData: String,
    signature: String,
    userHandle: Option[String]
)
