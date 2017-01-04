#!/usr/bin/env amm
/**
  * Script to analyse a bind file and the domains within for HSTS readiness
  */

import $ivy.`dnsjava:dnsjava:2.1.7`
import $ivy.`org.typelevel::cats:0.8.1`
import $ivy.`org.scalaj::scalaj-http:2.3.0`
import $ivy.`com.lihaoyi::fansi:0.2.3`
import org.xbill.DNS.{Record => JRecord, Master, Type}

import java.io.{File, PrintStream}
import java.net.{ConnectException, UnknownHostException, SocketTimeoutException}
import javax.net.ssl.SSLHandshakeException

import scala.util.control.NonFatal

import cats.syntax.either._
import scalaj.http._
import fansi._

sealed trait TestResult
case class Success(hstsHeader: Option[HstsHeader]) extends TestResult
trait Failed extends TestResult
case object Unresolvable extends Failed
case object Unreachable extends Failed
case object ConnectionRefused extends Failed
case class SSLHandshakeFailed(message: String) extends Failed

case class HstsHeader(maxAge: Option[Long], includeSubdomains: Boolean, preload: Boolean)
object HstsHeader {
  def apply(headerValue: String): Either[FailureReason, HstsHeader] = {
    try {
      val components = headerValue.split(';').map(_.trim).filterNot(_.isEmpty)
      val includeSubDomains = components.contains("includeSubDomains")
      val preload = components.contains("preload")
      val maxAge = components.find(_.startsWith("max-age=")).map { maxAgeFragment =>
        maxAgeFragment.stripPrefix("max-age=").toLong
      }
      Right(HstsHeader(maxAge, includeSubDomains, preload))
    } catch {
      case NonFatal(e) => Left(FailureReason(s"${e.getMessage}"))
    }
  }
}

case class ResultPair(http: TestResult, https: TestResult) {
  val causeForConcern = (http, https) match {
    case (Success(_), Success(Some(header))) => false
    case (Success(_), _) => true
    case _ => false
  }
  val hsts = https match {
    case Success(header) => header
    case _ => None
  }
}

case class FailureReason(message: String) extends AnyVal

/** Adaptor to turn a BIND master file parser into a Scala iterator of DNS
  * records
  */
class MasterIterator(master: Master) extends Iterator[JRecord] {
  var nextRecord = Option(master.nextRecord())
  def hasNext = nextRecord.nonEmpty
  def next() = {
    val next = nextRecord.get
    nextRecord = Option(master.nextRecord())
    next
  }
}

/* Case class representing a DNS record */
case class Record(name: String, ttl: Long, typeName: String, resourceRecord: String)
object Record {
  /* apply method that takes a dnsjava record type */
  def apply(jr: JRecord): Record =
    Record(jr.getName.toString, jr.getTTL, Type.string(jr.getType), jr.rdataToString)
}

def loadBindFile(bindFile: File): List[Record] = {
  val bindFileParser = new Master(bindFile.toString)
  val jRecords = new MasterIterator(bindFileParser).toList
  jRecords.map(Record.apply)
}

def testConn(record: Record, https: Boolean): Either[FailureReason, TestResult] = {
  val stripped = record.name.stripSuffix(".")
  val url = s"http${if (https) "s" else ""}://$stripped/"
  try {
    val response = Http(url).asString
    val hstsHeader = response.header("Strict-Transport-Security")
    hstsHeader.map(HstsHeader.apply) match {
      case Some(header) => header.map(h => Success(Some(h)))
      case None => Right(Success(None))
    }
  } catch {
    case _:UnknownHostException => Right(Unresolvable)
    case _:SocketTimeoutException => Right(Unreachable)
    case _:ConnectException => Right(ConnectionRefused)
    case sslFailed:SSLHandshakeException => Right(SSLHandshakeFailed(sslFailed.getMessage))
    case NonFatal(e) => Left(FailureReason(s"WTF? ${e.getClass} ${e.getMessage}"))
  }
}

type PossibleResult = (Record, Either[FailureReason, ResultPair])
type Result = (Record, ResultPair)
type ReportGenerator = List[Result] => Option[Report]
type RecordsByType = Map[String, List[Record]]

def testRecords(records: List[Record])(progress: (Int, Int) => Unit = (_,_) => ()): List[PossibleResult] = {
  records.zipWithIndex.map { case (record, index) =>
    progress(index+1, records.size)
    val testResult = for {
      httpsResult <- testConn(record, https = true)
      httpResult <- testConn(record, https = false)
    } yield ResultPair(httpResult, httpsResult)
    record -> testResult
  }
}

case class Report(lines: List[Str])

val csvReportGenerator: ReportGenerator = { results =>
  def csvValue(result: TestResult) = {
    result match {
      case Unreachable => "unreachable"
      case Unresolvable => "unresolvable"
      case ConnectionRefused => "connection_refused"
      case SSLHandshakeFailed(_) => "ssl_error"
      case Success(_) => "success"
    }
  }

  val header = Str("Name,Type,Value,HTTP,HTTPS,HSTS max-age,HSTS includeSubDomains,HSTS preload")
  val data = results.map { case (record, pair) =>
    val hsts = pair.hsts
    Str(s"${record.name},${record.typeName},${record.resourceRecord},${csvValue(pair.http)},${csvValue(pair.https)},${hsts.map(_.maxAge).getOrElse("")},${hsts.map(_.includeSubdomains).getOrElse("")},${hsts.map(_.preload).getOrElse("")}")
  }

  Some(Report(header :: data))
}

def terminalReportGenerator(verbose: Boolean, ansi: Boolean = true): ReportGenerator = { results =>
  def pr(msg: Str, width: Option[Int] = None): Str = {
    val padding = width.map(_ - msg.length).getOrElse(0)
    msg ++ Str(" " * padding)
  }
  
  def terminalValue(result: TestResult, causeForConcern: Boolean) = {
    def error(message: String) = {
      Str(message).overlay(if(causeForConcern) Color.Red else Color.Yellow)
    }
    result match {
      case Unreachable => error("Unreachable")
      case Unresolvable => error("Unresolvable")
      case ConnectionRefused => error("Connection Refused")
      case SSLHandshakeFailed(_) => Color.Red("SSL Error")
      case Success(_) => Color.Green("Success")
    }
  }

  val resultsToOutput = if (verbose) results else results.filter(_._2.causeForConcern)
  val maybeWarning = if (resultsToOutput.size < results.size)
    List(
      Str(s"${results.size - resultsToOutput.size} record results look fine and are not shown"),
      Str("NOTE: this includes hosts that are unreachable on both HTTP and HTTPS, to see the full list use the verbose flag")
    ) else Nil

  if (resultsToOutput.nonEmpty) {
    val maxNameWidth = resultsToOutput.map{case (record, _) => record.name.length}.max
    val reportHeader = Color.Yellow(s"WARNING: ${resultsToOutput.size} records point to servers that are available over HTTP but not over HTTPS or do not have HSTS headers")
    val header =
      pr(Str("  ")) ++
      pr(Color.White("Record Name"), Some(maxNameWidth+2)) ++
      pr(Color.White("HTTP Result"), Some(20)) ++
      pr(Color.White("HTTPS Result"), Some(20)) ++
      pr(Color.White("HSTS Header (ma, isd, pl"))
    val rows = resultsToOutput.sortBy(_._1.name).map { case (record, pair) =>
      val name = Str(s"${record.name}")
      val hsts = pair.hsts.map{ header =>
        val maxAge = header.maxAge.getOrElse(0L)
        Str(s"$maxAge${if(header.includeSubdomains){", isd"} else {""}}${if(header.preload){", pl"}else{""}}")
          .overlay(if (maxAge < 10886400L) Color.Yellow else Color.Green)
      }.getOrElse(Color.Yellow("No header"))
      pr(Str("  ")) ++
      pr(name, Some(maxNameWidth+2)) ++
      pr(terminalValue(pair.http, causeForConcern = false), Some(20)) ++
      pr(terminalValue(pair.https, pair.causeForConcern), Some(20)) ++
      pr(hsts)
    }
    Some(Report((reportHeader :: header :: rows) ++ maybeWarning))
  } else {
    None
  }
}

def aAndCnameReport(recordsByType: RecordsByType, outputFormat: String, verbose: Boolean, limit: Int): Either[Report, Option[Report]] = {
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
  val simpleRecords = recordsByType("A") ::: recordsByType("CNAME")
  val limitedRecords = if (limit == 0) simpleRecords else simpleRecords.take(limit)
  val possibleResults = testRecords(limitedRecords){ (soFar, total) =>
    System.err.print(s"\r$soFar/$total")
  }
  System.err.println()

  val (errors, results) = possibleResults.foldLeft[(List[(Record, FailureReason)], List[Result])]((Nil, Nil)){
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

def delegatedZonesReport(recordsByType: RecordsByType): Either[Report, Option[Report]] = {
  val nsRecords = recordsByType("NS")
  if (nsRecords.isEmpty) {
    Right(None)
  } else {
    val delegatedZones = nsRecords.filterNot(_.name.isEmpty).map(_.name).distinct.sorted
    val header = Color.Yellow(s"WARNING: ${delegatedZones.size} subdomains are delegated to external zones - it is not possible to fully analyse this zone. Please check these zones individually.")
    val rows = delegatedZones.map(zone => Color.White(s"  $zone"))
    Right(Some(Report(header :: rows)))
  }
}

def dnameZonesReport(recordsByType: RecordsByType): Either[Report, Option[Report]] = {
  val dnameRecords = recordsByType("DNAME")
  if (dnameRecords.isEmpty) {
    Right(None)
  } else {
    val delegatedZones = dnameRecords.map(_.name).distinct.sorted
    val header = Color.Yellow(s"WARNING: ${delegatedZones.size} subdomains use DNAME to delegate to external zones - it is not possible to fully analyse this zone. Please check these records individually.")
    val rows = delegatedZones.map(zone => Color.White(s"  $zone"))
    Right(Some(Report(header :: rows)))
  }
}

def aaaaReport(recordsByType: RecordsByType): Either[Report, Option[Report]] = {
  val aaaaRecords = recordsByType("AAAA")
  if (aaaaRecords.isEmpty) {
    Right(None)
  } else {
    val ipv6Records = aaaaRecords.map(_.name).distinct.sorted
    val header = Color.Yellow(s"WARNING: There are ${ipv6Records.size} AAAA (IPv6) records - this tool does not currently separately analyse IPv6 so you are advised to check these records manually.")
    val rows = ipv6Records.map(zone => Color.White(s"  $zone"))
    Right(Some(Report(header :: rows)))
  }
}

def outputReport(report: Report, stream: PrintStream, ansi: Boolean = true): Unit = {
  report.lines.foreach { line =>
    stream.println(if (ansi) line else line.plainText)
  }
}

def printReports(results: List[Either[Report, Option[Report]]]) = {
  val (errorReports, resultReports) = results.foldLeft[(List[Report], List[Report])](Nil, Nil) { case ((errAcc, resAcc), either) =>
    either.fold(
      err => (errAcc :+ err, resAcc),
      res => (errAcc, resAcc ++ res)
    )
  }
  if (errorReports.nonEmpty) {
    errorReports.foreach(outputReport(_, System.err))
    System.exit(1)
  } else {
    resultReports.foreach { report =>
      outputReport(report, System.out)
      System.out.println()
    }
  }
}

@main
def main(file: File, output: String = "terminal", verbose: Boolean = false, limit: Int = 0) {
  System.err.println("Loading master file")
  val records = loadBindFile(file)
  val recordsByType = records.groupBy(_.typeName).withDefaultValue(Nil)
  val results =
    aAndCnameReport(recordsByType, output, verbose, limit) ::
    delegatedZonesReport(recordsByType) ::
    dnameZonesReport(recordsByType) ::
    aaaaReport(recordsByType) ::
    Nil
  printReports(results)
}