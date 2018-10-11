package com.gu.hstschecker.reports

import com.gu.hstschecker.dns.Zone
import fansi.Color

object Wildcard {
  def report(zone: Zone): Either[Report, Option[Report]] = {
    val aAndCname = zone.allRecordsByType("A") ::: zone.allRecordsByType("CNAME")
    val wildcards = aAndCname.filter(_.name.startsWith("*"))
    if (wildcards.isEmpty) {
      Right(None)
    } else {
      val delegatedZones = wildcards.map(_.name).distinct.sorted
      val header = Color.Yellow(s"WARNING: ${delegatedZones.size} wildcard record(s) exist(s) - it is not possible to fully analyse this zone. Please check these entries individually.")
      val rows = delegatedZones.map(zone => Color.White(s"  $zone"))
      Right(Some(Report(header :: rows)))
    }
  }
}
