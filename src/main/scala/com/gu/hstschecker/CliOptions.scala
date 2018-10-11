package com.gu.hstschecker

import java.io.File

import scopt.OptionParser

sealed trait OutputMode
case object Terminal extends OutputMode
case object CSV extends OutputMode

object OutputMode {
  implicit val read: scopt.Read[OutputMode] =
    scopt.Read.stringRead.map {
      case "terminal" => Terminal
      case "csv" => CSV
      case invalid => throw new IllegalArgumentException(s"$invalid isn't a valid output mode")
    }
}

case class CliOptions(output: OutputMode = Terminal,
                      verbose: Boolean = false,
                      limit: Int = 0,
                      bindFile: Option[File] = None,
                      route53Zone: Option[String] = None,
                      awsRegion: Option[String] = None,
                      awsProfiles: Seq[String] = Seq.empty
                     )

object CliOptions {
  val parser: OptionParser[CliOptions] = new scopt.OptionParser[CliOptions]("hsts-checker") {
    head("hsts-checker", "1.0")

    opt[OutputMode]('o', "output").action((x, c) =>
      c.copy(output = x)).text("output mode (terminal or csv, defaults to terminal)")

    opt[Unit]('v', "verbose").action((_, c) =>
      c.copy(verbose = true)).text("enable verbose logging")

    opt[Int]('l', "limit").action((x, c) =>
      c.copy(limit = x)).text("restrict processing to the first N records")

    opt[File]('b', "bind-file").action((x, c) =>
      c.copy(bindFile = Some(x))).text("specify a bind format file")

    opt[String]('z', "zone").action((x, c) =>
      c.copy(route53Zone = Some(x))
    ).text("specify the name of a route53 zone")

    opt[String]('r', "region").action((x, c) =>
      c.copy(awsRegion = Some(x))
    ).text("specify the AWS region")

    opt[Seq[String]]('p', "profiles").action((x, c) =>
      c.copy(awsProfiles = x)
    ).text("specify the AWS profiles to use for credentials (comma separated list)")
  }
}
