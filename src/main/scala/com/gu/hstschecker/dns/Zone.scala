package com.gu.hstschecker.dns

case class Zone(records: List[Record]) {
  val recordsByType: Map[String, List[Record]] = records.groupBy(_.typeName).withDefaultValue(Nil)
  val name: String = recordsByType("SOA").head.name
}
