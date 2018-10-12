package com.gu.hstschecker.reports

import com.gu.hstschecker.dns.{DelegatedZone, Zone}
import fansi.{Color, Str}

object DelegatedZones {
  def report(zone: Zone): Either[Report, Option[Report]] = {
    val delegatedZones = zone.allZones.collect{ case delegated: DelegatedZone => delegated }.sortBy(_.name)
    if (delegatedZones.isEmpty) {
      Right(None)
    } else {
      val header = Color.Yellow(s"WARNING: ${delegatedZones.size} subdomains are delegated to external zones - it is not possible to fully analyse these zone. Please check these zones individually.")
      val rows: List[Str] = delegatedZones.map(zone => Color.White(s"  ${zone.name}") ++ s" - ${zone.reason}")
      Right(Some(Report(header :: rows)))
    }
  }
}
