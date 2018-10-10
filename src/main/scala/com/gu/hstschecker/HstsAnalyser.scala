package com.gu.hstschecker
/**
  * Script to analyse a bind file and the domains within for HSTS readiness
  */

import java.io.{File, PrintStream}
import java.net.{ConnectException, SocketException, SocketTimeoutException, UnknownHostException}

import com.gu.hstschecker.dns.{BindFile, Record}
import com.gu.hstschecker.reports._
import javax.net.ssl.{SSLHandshakeException, SSLProtocolException}

import scala.util.control.NonFatal
import scalaj.http._
import fansi._

sealed trait TestResult {
  def csvValue: String
  def friendlyName: String
}
case class Success(hstsHeader: Option[HstsHeader], locationHeader: Option[String]) extends TestResult {
  override def csvValue = "success"
  override def friendlyName = "Success"
}
trait Failed extends TestResult
case object Unresolvable extends Failed {
  override def csvValue: String = "unresolvable"
  override def friendlyName: String = "Unresolvable"
}
case object Unreachable extends Failed {
  override def csvValue: String = "unreachable"
  override def friendlyName: String = "Unreachable"
}
case object ConnectionRefused extends Failed {
  override def csvValue = "connection_refused"
  override def friendlyName = "Connection refused"
}
case class ConnectionFailed(message: String) extends Failed {
  override def csvValue: String = "connection"
  val truncatedMessage = if (message.length > 35) message.take(34) + "…" else message
  override def friendlyName = {
    s"Connection Error: $truncatedMessage"
  }
}
case class SSLHandshakeFailed(message: String) extends Failed {
  override def csvValue = "ssl_error"
  val truncatedMessage = if (message.length > 35) message.take(34) + "…" else message
  override def friendlyName = {
    s"SSL Error: $truncatedMessage"
  }
}

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
    case (Success(_, _), Success(Some(header), _)) => false
    case (Success(_, _), _) => true
    case _ => false
  }
  val hsts = https match {
    case Success(header, _) => header
    case _ => None
  }
}

case class FailureReason(message: String) extends AnyVal

object HstsAnalyser {
  def testConn(record: Record, https: Boolean): Either[FailureReason, TestResult] = {
    val stripped = record.name.stripSuffix(".")
    val url = s"http${if (https) "s" else ""}://$stripped/"
    try {
      val response = Http(url).option(HttpOptions.followRedirects(false)).asString
      val hstsHeader = response.header("Strict-Transport-Security")
      val locationHeader = response.header("Location")
      hstsHeader.map(HstsHeader.apply) match {
        case Some(header) => header.map(h => Success(Some(h), locationHeader))
        case None => Right(Success(None, locationHeader))
      }
    } catch {
      case _: UnknownHostException => Right(Unresolvable)
      case _: SocketTimeoutException => Right(Unreachable)
      case _: ConnectException => Right(ConnectionRefused)
      case connectFailed: SocketException => Right(ConnectionFailed(connectFailed.getMessage))
      case sslFailed: SSLHandshakeException => Right(SSLHandshakeFailed(sslFailed.getMessage))
      case sniError: SSLProtocolException => Right(SSLHandshakeFailed(sniError.getMessage))
      case NonFatal(e) => Left(FailureReason(s"WTF? ${e.getClass} ${e.getMessage}"))
    }
  }

  type PossibleResult = (Record, Either[FailureReason, ResultPair])
  type Result = (Record, ResultPair)
  type ReportGenerator = List[Result] => Option[Report]
  type RecordsByType = Map[String, List[Record]]

  def testRecords(records: List[Record])(progress: (Int, Int) => Unit = (_, _) => ()): List[PossibleResult] = {
    var counter = 0
    progress(0, records.size)
    records.par.map { case record =>
      val testResult = for {
        httpsResult <- testConn(record, https = true)
        httpResult <- testConn(record, https = false)
      } yield ResultPair(httpResult, httpsResult)

      // brutally simple thread safety: lock on the incoming list object
      records.synchronized {
        counter += 1
        progress(counter, records.size)
      }

      record -> testResult
    }.toList
  }



  def main(file: File, output: String = "terminal", verbose: Boolean = false, limit: Int = 0) {
    System.err.println("Loading master file")
    val inputStream = BindFile.loadBindFile(file)
    val zone = BindFile.parseBindData(inputStream)
    val results =
      AandCNAME.report(zone, output, verbose, limit) ::
        DelegatedZones.report(zone) ::
        DNAME.report(zone) ::
        AAAA.report(zone) ::
        Preload.report(zone) ::
        Nil
    System.err.println()
    Report.printReports(results)
  }
}