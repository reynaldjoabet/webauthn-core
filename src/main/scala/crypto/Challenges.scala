package webauthn.crypto

import webauthn.domain.ChallengeBytes

import java.security.SecureRandom

/** Cryptographically secure challenge generation (WebAuthn §13.4.3 recommends
  * at least 16 bytes of entropy; 32 is a common default).
  */
object Challenges {

  /** Minimum challenge length the spec recommends. */
  val MinLength: Int = 16

  /** Default challenge length used when none is specified. */
  val DefaultLength: Int = 32

  private val random = new SecureRandom()

  def generate(length: Int = DefaultLength): ChallengeBytes = {
    require(
      length >= MinLength,
      s"challenge must be at least $MinLength bytes, got $length"
    )
    val buffer = new Array[Byte](length)
    random.nextBytes(buffer)
    ChallengeBytes.applyUnsafe(buffer.toVector)
  }
}
