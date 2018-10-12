package com.gu.hstschecker.dns

import java.io.{ByteArrayInputStream, File, InputStream}

import com.gu.hstschecker.util.Failure
import org.xbill.DNS.{Master, Record => JRecord}

import scala.io.Source

object BindFile {
  /** Adaptor to turn a BIND master file parser into a Scala iterator of DNS
    * records
    */
  class MasterIterator(master: Master) extends Iterator[JRecord] {
    var nextRecord = Option(master.nextRecord())
    def hasNext: Boolean = nextRecord.nonEmpty
    def next(): JRecord = {
      val next = nextRecord.get
      nextRecord = Option(master.nextRecord())
      next
    }
  }

  /* This is an almighty hack to deal with Dyn giving us CNAME records that have priorities */
  def cleanDynCname(line: String): String = {
    val DynCnameRegex = """([a-zA-Z@-_]*\s+)(\d+\s+)CNAME\s+\d+(\s+.*)""".r
    line match {
      case DynCnameRegex(name, ttl, resourceRecord) => s"$name${ttl}CNAME$resourceRecord"
      case other => other
    }
  }

  def loadBindFile(bindFile: File): InputStream = {
    System.err.println("Loading master file")
    val bindContents = Source.fromFile(bindFile, "ASCII")
    val bindLines = bindContents.getLines
    val cleanedLines = bindLines.map(cleanDynCname)
    new ByteArrayInputStream(cleanedLines.mkString("\n").getBytes("ASCII"))
  }

  def parseBindData(bindData: InputStream): Either[Failure, Zone] = {
    val bindFileParser = new Master(bindData)
    val jRecords = new MasterIterator(bindFileParser).toList
    val records = jRecords.map(Record.apply)
    Right(Zone(records))
  }
}
