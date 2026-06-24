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

type SignCount = SignCount.T
object SignCount extends RefinedType[Long, Positive0]

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

  def wire: String =
    this match {
      case PublicKey => "public-key"
    }
}

enum ClientDataType derives CanEqual {
  case Create
  case Get

  def wire: String =
    this match {
      case Create => "webauthn.create"
      case Get    => "webauthn.get"
    }
}

enum AuthenticatorTransport derives CanEqual {
  case Usb
  case Nfc
  case Ble
  case SmartCard
  case Hybrid
  case Internal
  case Unknown(value: String)

  def wire: String =
    this match {
      case Usb            => "usb"
      case Nfc            => "nfc"
      case Ble            => "ble"
      case SmartCard      => "smart-card"
      case Hybrid         => "hybrid"
      case Internal       => "internal"
      case Unknown(value) => value
    }
}

enum AuthenticatorAttachment derives CanEqual {
  case Platform
  case CrossPlatform

  def wire: String =
    this match {
      case Platform      => "platform"
      case CrossPlatform => "cross-platform"
    }
}

enum ResidentKeyRequirement derives CanEqual {
  case Discouraged
  case Preferred
  case Required

  def wire: String =
    this match {
      case Discouraged => "discouraged"
      case Preferred   => "preferred"
      case Required    => "required"
    }
}

enum UserVerificationRequirement derives CanEqual {
  case Required
  case Preferred
  case Discouraged

  def wire: String =
    this match {
      case Required    => "required"
      case Preferred   => "preferred"
      case Discouraged => "discouraged"
    }
}

enum AttestationConveyancePreference derives CanEqual {
  case None
  case Indirect
  case Direct
  case Enterprise

  def wire: String =
    this match {
      case None       => "none"
      case Indirect   => "indirect"
      case Direct     => "direct"
      case Enterprise => "enterprise"
    }
}

enum PublicKeyCredentialHint derives CanEqual {
  case SecurityKey
  case ClientDevice
  case Hybrid
  case Unknown(value: String)

  def wire: String =
    this match {
      case SecurityKey    => "security-key"
      case ClientDevice   => "client-device"
      case Hybrid         => "hybrid"
      case Unknown(value) => value
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
  case Compound
  case Unknown(value: String)

  def wire: String =
    this match {
      case None             => "none"
      case Packed           => "packed"
      case Tpm              => "tpm"
      case AndroidKey       => "android-key"
      case AndroidSafetyNet => "android-safetynet"
      case FidoU2f          => "fido-u2f"
      case Apple            => "apple"
      case Compound         => "compound"
      case Unknown(value)   => value
    }
}

enum TokenBindingStatus derives CanEqual {
  case Present
  case Supported

  def wire: String =
    this match {
      case Present   => "present"
      case Supported => "supported"
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

final case class AuthenticationExtensionsClientInputs(
    values: Map[String, ExtensionInput]
)

enum ExtensionInput {
  case Bool(value: Boolean)
  case Text(value: String)
  case Bytes(value: NonEmptyBytes)
  case JsonObject(value: Map[String, ExtensionInput])
}

final case class PublicKeyCredentialCreationOptions(
    rp: PublicKeyCredentialRpEntity,
    user: PublicKeyCredentialUserEntity,
    challenge: ChallengeBytes,
    pubKeyCredParams: Vector[PublicKeyCredentialParameters],
    timeout: Option[TimeoutMillis],
    excludeCredentials: Vector[PublicKeyCredentialDescriptor],
    authenticatorSelection: Option[AuthenticatorSelectionCriteria],
    hints: Vector[PublicKeyCredentialHint],
    attestation: AttestationConveyancePreference,
    attestationFormats: Vector[AttestationStatementFormat],
    extensions: Option[AuthenticationExtensionsClientInputs]
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
    hints: Vector[PublicKeyCredentialHint],
    extensions: Option[AuthenticationExtensionsClientInputs]
)

// ---------------------------------------------------------------------------
// Browser response domain: browser -> server
// ---------------------------------------------------------------------------

final case class CollectedClientData(
    typ: ClientDataType,
    challenge: Base64UrlNoPadding,
    origin: Origin,
    crossOrigin: Boolean,
    topOrigin: Option[Origin],
    tokenBinding: Option[TokenBinding]
)

final case class TokenBinding(
    status: TokenBindingStatus,
    id: Option[NonBlankText]
)

final case class ClientExtensionOutputs(
    values: Map[String, ExtensionOutput]
)

enum ExtensionOutput {
  case Bool(value: Boolean)
  case Text(value: String)
  case Bytes(value: NonEmptyBytes)
  case JsonObject(value: Map[String, ExtensionOutput])
}

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
)

final case class AttestedCredentialData(
    aaguid: Aaguid,
    credentialId: CredentialId,
    credentialPublicKey: CredentialPublicKey
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

final case class AuthenticatorExtensionOutputs(
    values: Map[String, ExtensionOutput]
)

final case class ParsedAttestationObject(
    fmt: AttestationStatementFormat,
    authData: AuthenticatorData,
    attStmt: AttestationStatement
)

final case class AttestationStatement(
    fmt: AttestationStatementFormat,
    cbor: NonEmptyBytes
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

  final case class CeremonyExpired(id: CeremonyId) extends WebAuthnError {
    override val message: String =
      "WebAuthn ceremony has expired"
  }

  final case class UserVerificationRequired() extends WebAuthnError {
    override val message: String =
      "User verification was required but the UV flag was not set"
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
