package com.gu.hstschecker.reports

import com.gu.hstschecker.dns.Zone
import fansi.Color

object DelegatedZones {
  def report(zone: Zone): Either[Report, Option[Report]] = {
    val nsRecords = zone.recordsByType("NS").filterNot(_.name == zone.name)
    if (nsRecords.isEmpty) {
      Right(None)
    } else {
      val delegatedZones = nsRecords.map(_.name).distinct.sorted
      val header = Color.Yellow(s"WARNING: ${delegatedZones.size} subdomains are delegated to external zones - it is not possible to fully analyse this zone. Please check these zones individually.")
      val rows = delegatedZones.map(zone => Color.White(s"  $zone"))
      Right(Some(Report(header :: rows)))
    }
  }
}
