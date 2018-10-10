package com.gu.hstschecker.dns

import org.xbill.DNS.{Type, Record => JRecord}

/* Case class representing a DNS record */
case class Record(name: String, ttl: Long, typeName: String, resourceRecord: String)
object Record {
  /* apply method that takes a dnsjava record type */
  def apply(jr: JRecord): Record =
    Record(jr.getName.toString, jr.getTTL, Type.string(jr.getType), jr.rdataToString)
}