package com.gu.hstschecker.reports

import com.gu.hstschecker.dns.Zone
import fansi.Color

object DNAME {
  def report(zone: Zone): Either[Report, Option[Report]] = {
    val dnameRecords = zone.recordsByType("DNAME")
    if (dnameRecords.isEmpty) {
      Right(None)
    } else {
      val delegatedZones = dnameRecords.map(_.name).distinct.sorted
      val header = Color.Yellow(s"WARNING: ${delegatedZones.size} subdomains use DNAME to delegate to external zones - it is not possible to fully analyse this zone. Please check these records individually.")
      val rows = delegatedZones.map(zone => Color.White(s"  $zone"))
      Right(Some(Report(header :: rows)))
    }
  }
}
