import Dependencies as deps

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
      deps.domain.iron.core,
      deps.domain.iron.jsoniter,
      deps.json.circe.core,
      deps.security.bouncycastle.pkix,
      deps.security.bouncycastle.provider,
      deps.security.webauthn.server,
      deps.security.webauthn.attestation,
      deps.testing.munit,
      deps.testing.scalacheck
    ) ++ deps.json.jsoniter.core
  )
