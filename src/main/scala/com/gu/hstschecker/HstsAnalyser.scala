package com.gu.hstschecker
/**
  * Script to analyse a bind file and the domains within for HSTS readiness
  */

import java.io.File

import com.gu.hstschecker.connection.ResultPair
import com.gu.hstschecker.dns.{BindFile, Record}
import com.gu.hstschecker.reports._

object HstsAnalyser {

  type Result = (Record, ResultPair)
  type ReportGenerator = List[Result] => Option[Report]

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