package com.gu.hstschecker.reports

import com.gu.hstschecker.{FailureReason, HstsHeader, Success, TestResult}
import com.gu.hstschecker.HstsAnalyser.testConn
import com.gu.hstschecker.dns.Zone
import fansi.{Color, Str}

object Preload {
  def report(zone: Zone): Either[Report, Option[Report]] = {
    def good(message: String) = Color.Green(s"  ✓ $message")

    def bad(message: String) = Color.Red(s"  ⚠︎ $message")

    def checkHttp(zone: String, httpTest: TestResult): Vector[Str] = {
      val message = httpTest match {
        case Success(_, location) if !location.exists(_.toLowerCase.startsWith(s"https://$zone")) =>
          bad(s"Host is listening on HTTP but not sending an immediate redirect to https://$zone")
        case Success(_, _) => good(s"Host listening on http://$zone and redirecting to https://$zone")
        case _ => good(s"Host is not listening on http://$zone")
      }
      Vector(message)
    }

    def checkHttps(zone: String, httpsTest: TestResult): Vector[Str] = {
      val httpsAvailable = httpsTest match {
        case Success(_, _) => good(s"Valid HTTPS at https://$zone")
        case other => bad(s"HTTPS not working on https://$zone/: ${other.friendlyName}")
      }
      val hstsHeaderPresent = httpsTest match {
        case Success(Some(header), _) =>
          val maxAge = header match {
            case HstsHeader(Some(goodAge), _, _) if goodAge >= 10886400 =>
              good(s"HSTS max-age=$goodAge greater than eighteen weeks (10886400 seconds)")
            case HstsHeader(Some(badAge), _, _) =>
              bad(s"HSTS max-age=$badAge is less than eighteen weeks (10886400 seconds)")
            case HstsHeader(None, _, _) =>
              bad(s"HSTS max-age parameter is missing, must be set to at least eighteen weeks (10886400 seconds)")
          }
          val includeSubDomains = header match {
            case HstsHeader(_, true, _) => good("HSTS includeSubdomains is specified")
            case HstsHeader(_, false, _) => bad("HSTS includeSubdomains must be specified")
          }
          val preload = header match {
            case HstsHeader(_, _, true) => good("HSTS preload is specified")
            case HstsHeader(_, _, false) => bad("HSTS preload must be specified")
          }
          Vector(good("HSTS header set"), maxAge, includeSubDomains, preload)

        case Success(None, _) => Vector(bad("No HSTS header"))
        case _ => Vector.empty
      }
      httpsAvailable +: hstsHeaderPresent
    }

    System.err.println("Checking pre-load status of apex")

    val zoneName = zone.name.stripSuffix(".")

    val maybeApexRecord = zone.recordsByType("A").find(_.name == s"$zoneName.").toRight(
      FailureReason(s"No apex A record found for $zoneName - the preload check requires a server running on the apex of the domain")
    )

    maybeApexRecord match {
      case Left(reason) => Right(Some(Report(List(bad(reason.message)))))
      case Right(apexRecord) =>
        val results = for {
          httpTest <- testConn(apexRecord, https = false)
          httpsTest <- testConn(apexRecord, https = true)
        } yield {
          val httpCheck = checkHttp(zoneName, httpTest)
          val httpsCheck = checkHttps(zoneName, httpsTest)
          httpCheck ++ httpsCheck
        }
        results.fold(
          failure => Left(Report(List(Str(failure.message)))),
          lines => Right(Some(Report(
            Color.White("HSTS preload readiness report") ::
              lines.toList
          )))
        )
    }
  }
}
