package com.gu.hstschecker.reports

import java.io.PrintStream

import fansi.Str

case class Report(lines: List[Str]) {
  def +(line: Str) = this.copy(this.lines :+ line)
}

object Report {
  def outputReport(report: Report, stream: PrintStream, ansi: Boolean = true): Unit = {
    report.lines.foreach { line =>
      stream.println(if (ansi) line else line.plainText)
    }
  }

  def printReports(results: List[Either[Report, Option[Report]]]) = {
    val (errorReports, resultReports) = results.foldLeft[(List[Report], List[Report])](Nil, Nil) { case ((errAcc, resAcc), either) =>
      either.fold(
        err => (errAcc :+ err, resAcc),
        res => (errAcc, resAcc ++ res)
      )
    }
    if (errorReports.nonEmpty) {
      errorReports.foreach(outputReport(_, System.err))
      System.exit(1)
    } else {
      resultReports.foreach { report =>
        outputReport(report, System.out)
        System.out.println()
      }
    }
  }
}