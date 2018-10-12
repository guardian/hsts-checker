package com.gu.hstschecker.connection

import com.gu.hstschecker.reports.Preload.HstsHeader

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
  val truncatedMessage: String = if (message.length > 35) message.take(34) + "…" else message
  override def friendlyName: String = {
    s"Connection Error: $truncatedMessage"
  }
}
case class SSLHandshakeFailed(message: String) extends Failed {
  override def csvValue = "ssl_error"
  val truncatedMessage: String = if (message.length > 35) message.take(34) + "…" else message
  override def friendlyName: String = {
    s"SSL Error: $truncatedMessage"
  }
}