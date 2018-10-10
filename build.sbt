name := "hsts-checker"

version := "1.0.0"

libraryDependencies ++= Seq(
  "dnsjava" % "dnsjava" % "2.1.7",
  "org.typelevel" %% "cats" % "0.8.1",
  "org.scalaj" %% "scalaj-http" % "2.3.0",
  "com.lihaoyi" %% "fansi" % "0.2.3"
)