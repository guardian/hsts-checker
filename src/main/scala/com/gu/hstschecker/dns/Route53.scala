package com.gu.hstschecker.dns

import com.amazonaws.services.route53.model.{HostedZone, ListHostedZonesRequest, ListResourceRecordSetsRequest, ResourceRecordSet}
import com.amazonaws.services.route53.AmazonRoute53
import com.gu.hstschecker.util.{Failure, PaginatedAWSRequest, ResourceMissingFailure}
import cats.syntax.either._

import scala.collection.JavaConverters._

/*
Grab a zone from Route53
 */
object Route53 {
  def getZone(zoneName: String)(implicit route53: AmazonRoute53): Either[Failure, Zone] = {
    for {
      zoneId <- getHostedZone(zoneName)
      records <- getZoneRecords(zoneId)
      zone = Zone(records)
    } yield zone
  }

  def getZoneRecords(zoneId: String)(implicit route53: AmazonRoute53): Either[Failure, List[Record]] = {
    for {
      awsRecords <- PaginatedAWSRequest.run(route53.listResourceRecordSets)(_.getResourceRecordSets)(new ListResourceRecordSetsRequest(zoneId))
      records = awsRecords.flatMap(convertFromAwsRecordSet)
    } yield records
  }

  def convertFromAwsRecordSet(rrs: ResourceRecordSet): List[Record] = {
    rrs.getResourceRecords.asScala.toList.map { record =>
      Record(rrs.getName, rrs.getTTL, rrs.getType, record.getValue)
    }
  }

  def getHostedZone(domain: String)(implicit route53: AmazonRoute53): Either[Failure, String] = {
    for {
      hostedZones <- PaginatedAWSRequest.run(route53.listHostedZones)(_.getHostedZones)(new ListHostedZonesRequest)
      hostedZone <- findMatchingZone(hostedZones, s"${domain.stripSuffix(".")}.")
    } yield hostedZone.getId
  }

  private def findMatchingZone(hostedZones: List[HostedZone], domain: String): Either[Failure, HostedZone] = {
    val candidateZone = hostedZones
      .filter(z => domain.endsWith(z.getName)) // only interested in hosted zones that could host the domain
      .sortBy(-_.getName.length) // descending length of domain
      .headOption
    Either.fromOption(
      candidateZone,
      ResourceMissingFailure(s"No hosted zone found for $domain. Zones evaluated: ${hostedZones.map(_.getName).mkString(", ")}")
    )
  }
}
