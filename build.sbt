name := "hsts-checker"

version := "1.0.0"

scalacOptions += "-Ypartial-unification"

libraryDependencies ++= Seq(
  "dnsjava" % "dnsjava" % "2.1.8",
  "org.typelevel" %% "cats-core" % "1.4.0",
  "org.scalaj" %% "scalaj-http" % "2.4.1",
  "com.lihaoyi" %% "fansi" % "0.2.5",
  "com.amazonaws" % "aws-java-sdk-route53" % "1.11.425"
)