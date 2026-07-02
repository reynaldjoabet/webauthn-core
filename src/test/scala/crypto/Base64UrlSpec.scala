package webauthn.crypto

class Base64UrlSpec extends munit.FunSuite {

  test("encode/decode round-trips arbitrary bytes") {
    val bytes = Vector[Byte](0, 1, 127, -128, -1, 62, 63)
    val encoded = Base64Url.encode(bytes)
    assertEquals(Base64Url.decode(encoded.value), Right(bytes))
  }

  test("encoding never emits padding") {
    for (n <- 0 to 8) {
      val encoded = Base64Url.encode(Vector.fill[Byte](n)(42))
      assert(!encoded.value.contains("="), clue = encoded.value)
    }
  }

  test("decode rejects padded and non-url-safe input") {
    assert(Base64Url.decode("AAA=").isLeft, "padding must be rejected")
    assert(Base64Url.decode("a+b").isLeft, "'+' must be rejected")
    assert(Base64Url.decode("a/b").isLeft, "'/' must be rejected")
    assert(Base64Url.decode("a b").isLeft, "whitespace must be rejected")
  }

  test("decode accepts the empty string as zero bytes") {
    assertEquals(Base64Url.decode(""), Right(Vector.empty[Byte]))
  }
}
