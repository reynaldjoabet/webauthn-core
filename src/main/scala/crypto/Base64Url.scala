package webauthn.crypto

import webauthn.domain.Base64UrlNoPadding

import java.util.Base64
import scala.util.Try

/** base64url without padding (RFC 4648 §5), the encoding WebAuthn uses for all
  * binary values exchanged as JSON strings.
  */
object Base64Url {

  private val encoder = Base64.getUrlEncoder.withoutPadding
  private val decoder = Base64.getUrlDecoder

  def encode(bytes: Array[Byte]): Base64UrlNoPadding =
    Base64UrlNoPadding.applyUnsafe(encoder.encodeToString(bytes))

  def encode(bytes: Vector[Byte]): Base64UrlNoPadding =
    encode(bytes.toArray)

  /** Strict decode: the JDK decoder alone tolerates `=` padding, which WebAuthn
    * forbids, so the alphabet/padding check runs first.
    */
  def decode(value: String): Either[String, Vector[Byte]] =
    for {
      unpadded <- Base64UrlNoPadding
        .either(value)
        .left
        .map(_ => "Invalid base64url value: must be unpadded base64url")
      bytes <- Try(decoder.decode(unpadded.value).toVector).toEither.left
        .map(t => s"Invalid base64url value: ${t.getMessage}")
    } yield bytes
}
