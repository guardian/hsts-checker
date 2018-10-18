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

  override def toString: String = {
    def delegatedZones: String = {
      if (delegations.isEmpty) "" else {
        s"""
           |DELEGATED ZONES
           |---------------
           |${delegations.map(_.toString).mkString("\n").linesWithSeparators.map("    " + _).mkString}
         """.stripMargin
      }
    }

    s"""
       |ZONE $name
       |
       |RECORDS
       |-------
       |${allRecords.sorted.mkString("\n")}
       |
       |$delegatedZones
       |
     """.stripMargin
  }
}

case class DelegatedZone(name: String, reason: String) extends Zone {
  val records: List[Record] = Nil
  val delegations: List[Zone] = Nil

  override def toString: String = {
    s"""
       |ZONE $name
       |No data available
       |
     """.stripMargin
  }
}
