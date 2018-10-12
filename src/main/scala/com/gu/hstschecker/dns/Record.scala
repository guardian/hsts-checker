package com.gu.hstschecker.dns

import cats.instances.ordering
import org.xbill.DNS.{Type, Record => JRecord}

/* Case class representing a DNS record */
case class Record(name: String, ttl: Long, typeName: String, resourceRecords: List[String]) extends Ordered[Record] {
  override def toString: String = {
    s"$name: $typeName $ttl ${resourceRecords.mkString("; ")}"
  }

  import scala.math.Ordered.orderingToOrdered
  override def compare(that: Record): Int = (this.name, this.typeName, this.ttl) compare (that.name, that.typeName, that.ttl)
}
object Record {
  /* apply method that takes a dnsjava record type */
  def apply(jr: JRecord): Record =
    Record(jr.getName.toString, jr.getTTL, Type.string(jr.getType), List(jr.rdataToString))
}