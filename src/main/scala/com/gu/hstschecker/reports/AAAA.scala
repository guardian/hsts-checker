package com.gu.hstschecker.reports

import com.gu.hstschecker.dns.Zone
import fansi.Color

object AAAA {
  def report(zone: Zone): Either[Report, Option[Report]] = {
    val aaaaRecords = zone.recordsByType("AAAA")
    if (aaaaRecords.isEmpty) {
      Right(None)
    } else {
      val ipv6Records = aaaaRecords.map(_.name).distinct.sorted
      val header = Color.Yellow(s"WARNING: There are ${ipv6Records.size} AAAA (IPv6) records - this tool does not currently separately analyse IPv6 so you are advised to check these records manually.")
      val rows = ipv6Records.map(zone => Color.White(s"  $zone"))
      Right(Some(Report(header :: rows)))
    }
  }
}
