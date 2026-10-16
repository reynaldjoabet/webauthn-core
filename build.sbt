ThisBuild / scalaVersion      := "3.9.0"
ThisBuild / version           := "0.1.0-SNAPSHOT"
ThisBuild / semanticdbEnabled := true
ThisBuild / scalacOptions     := Seq(
  "-encoding",
  "UTF-8",
  "-no-indent",
  "-deprecation",
  "-feature",
  "-unchecked",
  // "-Werror",
  // "-Wunused:all",
  "-Wvalue-discard",
  "-Wnonunit-statement",
  "-language:strictEquality",
  "-Xcheck-macros",
  "-Xmax-inlines:64"
)

Global / onChangedBuildSource := ReloadOnSourceChanges

lazy val root = (project in file("."))
  .settings(
    name                 := "webauthn-core",
    libraryDependencies ++= Seq(
      Dependencies.domain.iron.core,
      Dependencies.domain.iron.jsoniter,
      Dependencies.json.circe.core,
      Dependencies.security.bouncycastle.pkix,
      Dependencies.security.bouncycastle.provider,
      Dependencies.security.webauthn.server,
      Dependencies.security.webauthn.attestation,
      Dependencies.testing.munit,
      Dependencies.testing.scalacheck
    ) ++ Dependencies.json.jsoniter.core
  )
