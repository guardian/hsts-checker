package com.gu.hstschecker.dns

sealed trait Zone {
  def records: List[Record]
  def name: String
  lazy val recordsByType: Map[String, List[Record]] = records.groupBy(_.typeName).withDefaultValue(Nil)
  lazy val allRecords: List[Record] = records ::: delegations.flatMap(_.allRecords)
  lazy val allRecordsByType: Map[String, List[Record]] = allRecords.groupBy(_.typeName).withDefaultValue(Nil)
  def delegations: List[Zone]
  def allZones: List[Zone] = this :: delegations.flatMap(_.allZones)
}

case class ActualZone(records: List[Record], delegations: List[Zone]) extends Zone {
  val name: String = recordsByType("SOA").head.name
}

case class DelegatedZone(name: String, reason: String) extends Zone {
  val records: List[Record] = Nil
  val delegations: List[Zone] = Nil
}
