package webauthn.domain

import io.circe.Json

// ---------------------------------------------------------------------------
// WebAuthn extensions (§9). Client extensions appear in the options sent to the
// browser and in `getClientExtensionResults()`; authenticator extensions are
// CBOR entries inside authenticator data.
//
// The IDL models each of these as a dictionary whose members are all optional
// and context-dependent (registration vs authentication). We mirror that with
// typed optional members for the extensions a relying party commonly acts on,
// plus an `unknown` map so unrecognised extensions round-trip without loss.
// ---------------------------------------------------------------------------

/** `largeBlob` support level requested at registration. */
enum LargeBlobSupport derives CanEqual {
  case Required
  case Preferred

  override def toString: String =
    this match {
      case Required  => "required"
      case Preferred => "preferred"
    }
}

object LargeBlobSupport {
  def fromString(value: String): Option[LargeBlobSupport] =
    value match {
      case "required"  => Some(Required)
      case "preferred" => Some(Preferred)
      case _           => Option.empty
    }
}

/** `largeBlob` inputs. `support` is used at registration; `read`/`write` are
  * mutually exclusive and used at authentication.
  */
final case class LargeBlobInputs(
    support: Option[LargeBlobSupport] = None,
    read: Option[Boolean] = None,
    write: Option[NonEmptyBytes] = None
)

final case class LargeBlobOutputs(
    supported: Option[Boolean] = None,
    blob: Option[NonEmptyBytes] = None,
    written: Option[Boolean] = None
)

/** A pair of PRF evaluation inputs/results; `second` enables the two-input
  * variant.
  */
final case class PrfValues(
    first: NonEmptyBytes,
    second: Option[NonEmptyBytes] = None
)

/** `prf` inputs. `eval` evaluates against the credential selected by the
  * ceremony; `evalByCredential` keys evaluations by base64url credential id.
  */
final case class PrfInputs(
    eval: Option[PrfValues] = None,
    evalByCredential: Map[NonEmptyBase64UrlNoPadding, PrfValues] = Map.empty
)

final case class PrfOutputs(
    enabled: Option[Boolean] = None,
    results: Option[PrfValues] = None
)

/** `credProps` output (`rk` = whether a discoverable/resident key was made). */
final case class CredentialPropertiesOutput(
    rk: Option[Boolean] = None
)

/** Client extension inputs (§9.1 client extension processing). Members are
  * populated per ceremony type; e.g. `credProps`/`appidExclude` at
  * registration, `appid` at authentication.
  */
final case class ClientExtensionInputs(
    appid: Option[String] = None,
    appidExclude: Option[String] = None,
    credProps: Option[Boolean] = None,
    largeBlob: Option[LargeBlobInputs] = None,
    prf: Option[PrfInputs] = None,
    unknown: Map[String, Json] = Map.empty
) {
  def isEmpty: Boolean =
    appid.isEmpty && appidExclude.isEmpty && credProps.isEmpty &&
      largeBlob.isEmpty && prf.isEmpty && unknown.isEmpty
}

object ClientExtensionInputs {
  val empty: ClientExtensionInputs = ClientExtensionInputs()
}

/** Client extension outputs from `getClientExtensionResults()`. */
final case class ClientExtensionOutputs(
    appid: Option[Boolean] = None,
    appidExclude: Option[Boolean] = None,
    credProps: Option[CredentialPropertiesOutput] = None,
    largeBlob: Option[LargeBlobOutputs] = None,
    prf: Option[PrfOutputs] = None,
    unknown: Map[String, Json] = Map.empty
)

object ClientExtensionOutputs {
  val empty: ClientExtensionOutputs = ClientExtensionOutputs()
}

/** CBOR `credProtect` policy, surfaced in authenticator extension outputs.
  * Carried on the wire as a CTAP2 uint (0x01–0x03).
  */
enum CredentialProtectionPolicy derives CanEqual {
  case UserVerificationOptional
  case UserVerificationOptionalWithCredentialIdList
  case UserVerificationRequired

  def label: Int =
    this match {
      case UserVerificationOptional                     => 1
      case UserVerificationOptionalWithCredentialIdList => 2
      case UserVerificationRequired                     => 3
    }
}

object CredentialProtectionPolicy {
  def fromLabel(label: Int): Option[CredentialProtectionPolicy] =
    label match {
      case 1 => Some(UserVerificationOptional)
      case 2 => Some(UserVerificationOptionalWithCredentialIdList)
      case 3 => Some(UserVerificationRequired)
      case _ => None
    }
}

/** Authenticator extension outputs carried in authenticator data (§9.2), e.g.
  * `credProtect`, `hmac-secret`, `uvm`. Unknown entries retain raw
  * CBOR-as-JSON.
  */
final case class AuthenticatorExtensionOutputs(
    credProtect: Option[CredentialProtectionPolicy] = None,
    hmacSecret: Option[Boolean] = None,
    unknown: Map[String, Json] = Map.empty
)

object AuthenticatorExtensionOutputs {
  val empty: AuthenticatorExtensionOutputs = AuthenticatorExtensionOutputs()
}
