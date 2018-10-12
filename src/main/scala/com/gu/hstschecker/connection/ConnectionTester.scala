package com.gu.hstschecker.connection

import java.net.{ConnectException, SocketException, SocketTimeoutException, UnknownHostException}

import com.gu.hstschecker.dns.Record
import com.gu.hstschecker.reports.Preload.HstsHeader
import com.gu.hstschecker.reports.Report.FailureReason
import javax.net.ssl.{SSLHandshakeException, SSLProtocolException}
import scalaj.http.{Http, HttpOptions}

import scala.util.control.NonFatal

object ConnectionTester {
  def test(record: Record, https: Boolean): Either[FailureReason, TestResult] = {
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
}
