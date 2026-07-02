package webauthn.crypto

import java.security.Provider

import org.bouncycastle.jce.provider.BouncyCastleProvider

/** The single BouncyCastle provider instance shared by this package.
  *
  * BouncyCastle covers what the platform providers lack: Ed25519 key material
  * from raw COSE bytes, and secp256k1 (removed from SunEC in JDK 16). The
  * instance is passed explicitly to `getInstance` calls rather than registered
  * globally via `Security.addProvider`, so this library never mutates JVM-wide
  * security configuration.
  */
private[crypto] object Providers {
  val bouncyCastle: Provider = new BouncyCastleProvider()
}
