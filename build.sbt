import Dependencies._

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
      iron,
      ironJsoniter,
      jsoniter,
      jsoniterMacros,
      bouncycastle,
      bouncycastleProvider,
      munit,
      scalacheck,
      circeCore,
      "com.yubico" % "webauthn-server-core"        % "2.9.0",
      "com.yubico" % "webauthn-server-attestation" % "2.9.0"
    )
  )
