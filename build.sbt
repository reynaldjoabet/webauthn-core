import Dependencies._

ThisBuild / scalaVersion := "3.3.8"
ThisBuild / version := "0.1.0-SNAPSHOT"

lazy val root = (project in file("."))
  .settings(
    name := "webauthn-core",
    libraryDependencies ++= Seq(
      iron,
      ironJsoniter,
      jsoniter,
      jsoniterMacros,
      bouncycastle,
      bouncycastleProvider,
      munit,
      scalacheck,
      circeCore,
      "com.yubico" % "webauthn-server-core" % "2.9.0",
      "com.yubico" % "webauthn-server-attestation" % "2.9.0"
    )
  )
