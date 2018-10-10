package com.gu.hstschecker.reports

import com.gu.hstschecker._
import com.gu.hstschecker.dns.{Record, Zone}
import com.gu.hstschecker.HstsAnalyser._
import com.gu.hstschecker.connection._
import com.gu.hstschecker.reports.Report.FailureReason
import fansi.{Color, Str}

object AandCNAME {

  type PossibleResult = (Record, Either[FailureReason, ResultPair])

  def report(zone: Zone, outputFormat: String, verbose: Boolean, limit: Int): Either[Report, Option[Report]] = {
    // do this first so that we error when the output option matches nothing
    val outputProcessor: ReportGenerator = outputFormat match {
      case "terminal" => terminalReportGenerator(verbose)
      case "csv" => csvReportGenerator
      case other =>
        System.err.println(s"$other is not a valid output format")
        System.exit(1)
        throw new RuntimeException(s"$other is not a valid output format")
    }

    System.err.println("Testing A and CNAME records")
    val simpleRecords = zone.recordsByType("A") ::: zone.recordsByType("CNAME")
    val limitedRecords = if (limit == 0) simpleRecords else simpleRecords.take(limit)
    val possibleResults = testRecords(limitedRecords) { (soFar, total) =>
      System.err.print(s"\r$soFar/$total")
    }
    System.err.println()

    val (errors, results) = possibleResults.foldLeft[(List[(Record, FailureReason)], List[Result])]((Nil, Nil)) {
      case ((errorAcc, resultAcc), (record, either)) =>
        either.fold(
          failure =>
            (errorAcc :+ (record, failure), resultAcc)
          ,
          result =>
            (errorAcc, resultAcc :+ (record, result))
        )
    }
    if (errors.nonEmpty) {
      val summary = Color.Yellow(s"ERROR: ${errors.size} errors encountered whilst checking A and CNAME records")
      val errorRows = errors.map { case (record, failureReason) =>
        Str(s"${record.name}: ${failureReason.message}")
      }
      Left(Report(summary :: errorRows))
    } else {
      Right(outputProcessor(results))
    }
  }

  private def testRecords(records: List[Record])(progress: (Int, Int) => Unit = (_, _) => ()): List[PossibleResult] = {
    var counter = 0
    progress(0, records.size)
    records.par.map { record =>
      val testResult = for {
        httpsResult <- ConnectionTester.test(record, https = true)
        httpResult <- ConnectionTester.test(record, https = false)
      } yield ResultPair(httpResult, httpsResult)

      // brutally simple thread safety: lock on the incoming list object
      records.synchronized {
        counter += 1
        progress(counter, records.size)
      }

      record -> testResult
    }.toList
  }

  private def terminalReportGenerator(verbose: Boolean, ansi: Boolean = true): ReportGenerator = { results =>
    def pr(msg: Str, width: Option[Int] = None): Str = {
      val padding = width.map(_ - msg.length).getOrElse(0)
      msg ++ Str(" " * padding)
    }

    def terminalValue(result: TestResult, causeForConcern: Boolean) = {
      def error(message: String) = {
        Str(message).overlay(if (causeForConcern) Color.Red else Color.Yellow)
      }

      result match {
        case SSLHandshakeFailed(_) => Color.Red(result.friendlyName)
        case Success(_, _) => Color.Green(result.friendlyName)
        case other => error(other.friendlyName)
      }
    }

    val resultsToOutput = if (verbose) results else results.filter(_._2.causeForConcern)
    val maybeWarning = if (resultsToOutput.size < results.size)
      List(
        Str(s"${results.size - resultsToOutput.size} record results look fine and are not shown (this includes hosts that are unreachable on both HTTP and HTTPS, to see the full list use the verbose flag)")
      ) else Nil

    if (resultsToOutput.nonEmpty) {
      val maxNameWidth = resultsToOutput.map { case (record, _) => record.name.length }.max
      val maxHttpWidth = resultsToOutput.map { case (_, ResultPair(http, _)) => http.friendlyName.length }.max
      val maxHttpsWidth = resultsToOutput.map { case (_, ResultPair(_, https)) => https.friendlyName.length }.max
      val reportHeader = Color.Yellow(s"WARNING: ${resultsToOutput.size} records point to servers that are available over HTTP but not over HTTPS or do not have HSTS headers")
      val header =
        pr(Str("  ")) ++
          pr(Color.White("Record Name"), Some(maxNameWidth + 2)) ++
          pr(Color.White("HTTP Result"), Some(maxHttpWidth + 2)) ++
          pr(Color.White("HTTPS Result"), Some(maxHttpsWidth + 2)) ++
          pr(Color.White("HSTS Header (ma, isd, pl)"))
      val rows = resultsToOutput.sortBy(_._1.name).map { case (record, pair) =>
        val name = Str(s"${record.name}")
        val hsts = pair.hsts.map { header =>
          val maxAge = header.maxAge.getOrElse(0L)
          Str(s"$maxAge${
            if (header.includeSubdomains) {
              ", isd"
            } else {
              ""
            }
          }${
            if (header.preload) {
              ", pl"
            } else {
              ""
            }
          }")
            .overlay(if (maxAge < 10886400L) Color.Yellow else Color.Green)
        }.getOrElse(Color.Yellow("No header"))
        pr(Str("  ")) ++
          pr(name, Some(maxNameWidth + 2)) ++
          pr(terminalValue(pair.http, causeForConcern = false), Some(maxHttpWidth + 2)) ++
          pr(terminalValue(pair.https, pair.causeForConcern), Some(maxHttpsWidth + 2)) ++
          pr(hsts)
      }
      Some(Report((reportHeader :: header :: rows) ++ maybeWarning))
    } else {
      None
    }
  }

  private val csvReportGenerator: ReportGenerator = { results =>
    val header = Str("Name,Type,Value,HTTP,HTTPS,HSTS max-age,HSTS includeSubDomains,HSTS preload")
    val data = results.map { case (record, pair) =>
      val hsts = pair.hsts
      Str(s"${record.name},${record.typeName},${record.resourceRecord},${pair.http.csvValue},${pair.https.csvValue},${hsts.map(_.maxAge).getOrElse("")},${hsts.map(_.includeSubdomains).getOrElse("")},${hsts.map(_.preload).getOrElse("")}")
    }

    Some(Report(header :: data))
  }
}
