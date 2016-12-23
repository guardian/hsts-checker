#!/usr/bin/env amm
/**
  * Script to analyse a bind file and the domains within for HSTS readiness
  */

import $ivy.`dnsjava:dnsjava:2.1.7`
import $ivy.`org.typelevel::cats:0.8.1`
import $ivy.`org.scalaj::scalaj-http:2.3.0`
import $ivy.`com.lihaoyi::fansi:0.2.3`
import org.xbill.DNS.{Record => JRecord, Master, Type, Address}

import java.io.{File, PrintStream}
import java.net.{ConnectException, UnknownHostException, SocketTimeoutException}
import javax.net.ssl.SSLHandshakeException

import scala.util.control.NonFatal

import cats.syntax.either._
import scalaj.http._
import fansi._

sealed trait TestResult
case class Success(hstsHeader: Option[String]) extends TestResult
trait Failed extends TestResult
case object Unresolvable extends Failed
case object Unreachable extends Failed
case object ConnectionRefused extends Failed
case class SSLHandshakeFailed(message: String) extends Failed

case class ResultPair(http: TestResult, https: TestResult) {
  val causeForConcern = (http, https) match {
    case (Success(_), Success(_)) => false
    case (Success(_), _) => true
    case _ => false
  }
  val hsts = https match {
    case Success(header) => Some(header)
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
    Right(Success(hstsHeader))
  } catch {
    case unknownHost:UnknownHostException => Right(Unresolvable)
    case unreachable:SocketTimeoutException => Right(Unreachable)
    case connectionRefused:ConnectException => Right(ConnectionRefused)
    case sslFailed:SSLHandshakeException => Right(SSLHandshakeFailed(sslFailed.getMessage))
    case NonFatal(e) => Left(FailureReason(s"WTF? ${e.getClass} ${e.getMessage}"))
  }
}

type Result = (Record, Either[FailureReason, ResultPair])

def testRecords(records: List[Record])(progress: (Int, Int) => Unit = (_,_) => ()): List[Result] = {
  records.zipWithIndex.map { case (record, index) =>
    progress(index+1, records.size)
    val testResult = for {
      httpsResult <- testConn(record, https = true)
      httpResult <- testConn(record, https = false)
    } yield ResultPair(httpResult, httpsResult)
    record -> testResult
  }
}

def resultsToCsv(results: List[Result], output: PrintStream) {
  def csvValue(result: TestResult) = {
    result match {
      case Unreachable => "unreachable"
      case Unresolvable => "unresolvable"
      case ConnectionRefused => "connection_refused"
      case SSLHandshakeFailed(_) => "ssl_error"
      case Success(_) => "success"
    }
  }

  output.println("Name,Type,Value,HTTP,HTTPS,HSTS")
  results.map { case (record, Right(pair)) =>
    val hsts = pair.hsts.getOrElse("")
    output.println(s"${record.name},${record.typeName},${record.resourceRecord},${csvValue(pair.http)},${csvValue(pair.https)},$hsts")
  }
}

def resultsToTerminal(results: List[Result], output: PrintStream, ansi: Boolean = true) {
  def formatStr(msg: Str) = if (ansi) msg else msg.plainText
  def pr(msg: Str, width: Option[Int] = None) = {
    val padding = width.map(_ - msg.length)
    output.print(msg)
    padding.foreach(p => output.print(" " * p))
  }
  def prl(msg: Str) = output.println(formatStr(msg))
  
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
  
  if (results.nonEmpty) {
    val maxNameWidth = results.map{case (record, _) => record.name.length}.max
    pr(Color.White("Record Name"), Some(maxNameWidth+2))
    pr(Color.White("HTTP Result"), Some(20))
    prl(Color.White("HTTPS Result"))
    results.sortBy(_._1.name).foreach{ case (record, Right(pair)) =>
      val name = Str(record.name)
      pr(name, Some(maxNameWidth+2))
      pr(terminalValue(pair.http, false), Some(20))
      prl(terminalValue(pair.https, pair.causeForConcern))
    }
  }
}

@main
def entrypoint(file: File, output: String = "terminal", limit: Int = 0) {
  System.err.println("Loading master file")
  val records = loadBindFile(file)
  val recordsByType = records.groupBy(_.typeName).withDefaultValue(Nil)
  val simpleRecords = recordsByType("A") ::: recordsByType("CNAME")
  val outputProcessor: List[Result] => Unit = output match {
    case "terminal" => (results) => resultsToTerminal(results, System.out)
    case "csv" => (results) => resultsToCsv(results, System.out)
  }
  System.err.println("Testing A and CNAME records")
  val limitedRecords = if (limit == 0) simpleRecords else simpleRecords.take(limit)
  val results = testRecords(limitedRecords){ (soFar, total) =>
    System.err.print(s"\r$soFar/$total")
  }
  System.err.println
  System.err.println
  outputProcessor(results)
}