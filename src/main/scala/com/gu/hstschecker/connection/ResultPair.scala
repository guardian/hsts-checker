package com.gu.hstschecker.connection

import com.gu.hstschecker.reports.Preload.HstsHeader

case class ResultPair(http: TestResult, https: TestResult) {
  val causeForConcern: Boolean = (http, https) match {
    case (Success(_, _), Success(Some(_), _)) => false
    case (Success(_, _), _) => true
    case _ => false
  }
  val hsts: Option[HstsHeader] = https match {
    case Success(header, _) => header
    case _ => None
  }
}