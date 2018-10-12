package com.gu.hstschecker.dns

import com.amazonaws.services.route53.model.{HostedZone, ListHostedZonesRequest, ListResourceRecordSetsRequest, ResourceRecordSet}
import com.amazonaws.services.route53.AmazonRoute53
import com.gu.hstschecker.util.{Failure, PaginatedAWSRequest, ResourceMissingFailure, CliOptionsFailure}
import cats.syntax.either._
import cats.syntax.traverse._
import cats.instances.either._
import cats.instances.list._

import scala.annotation.tailrec
import scala.collection.JavaConverters._

/*
Grab a zone from Route53
 */
object Route53 {
  def getDelegatedZones(zoneName: String, records: List[Record])(implicit route53: List[AmazonRoute53]): Either[Failure, List[Zone]] = {
    val delegatedZones =
      records
        .filter(_.typeName == "NS") // only NS records
        .filterNot(_.name.stripSuffix(".") == zoneName.stripSuffix(".")) // don't look at our own NS records

    delegatedZones.traverse { delegatedZone =>
      if (delegatedZone.resourceRecords.exists(_.contains("awsdns"))) {
        getZone(delegatedZone.name).leftFlatMap {
          case ResourceMissingFailure(_) => Right(DelegatedZone(delegatedZone.name, "Not in any of the AWS accounts provided"))
          case other => Left(other)
        }
      } else {
        Right(DelegatedZone(delegatedZone.name, "Not delegated to AWS"))
      }
    }
  }

  def getZone(zoneName: String)(implicit route53: List[AmazonRoute53]): Either[Failure, Zone] = {
    for {
      zoneId <- attemptWithMultipleClients(getHostedZone(zoneName)(_))
      records <- attemptWithMultipleClients(getZoneRecords(zoneId)(_))
      delegatedZones <- getDelegatedZones(zoneName, records)
      zone = ActualZone(records, delegatedZones)
    } yield zone
  }

  @tailrec
  def attemptWithMultipleClients[A](f: AmazonRoute53 => Either[Failure, A])(implicit route53: List[AmazonRoute53]): Either[Failure, A] = {
    route53 match {
      // if this is the last client then return the result regardless
      case last :: Nil => f(last)
      case next :: tail =>
        val result = f(next)
        // if successful return, otherwise proceed to try more clients
        if (result.isRight) result else attemptWithMultipleClients(f)(tail)
      case Nil => Left(CliOptionsFailure("No Route53 client provided"))
    }
  }

  def getZoneRecords(zoneId: String)(implicit route53: AmazonRoute53): Either[Failure, List[Record]] = {
    for {
      awsRecords <- PaginatedAWSRequest.run(route53.listResourceRecordSets)(_.getResourceRecordSets)(new ListResourceRecordSetsRequest(zoneId))
      records = awsRecords.map(convertFromAwsRecordSet)
    } yield records
  }

  def convertFromAwsRecordSet(rrs: ResourceRecordSet): Record = {
    val fixedName = rrs.getName.replace("\\052", "*")
    Record(fixedName, rrs.getTTL, rrs.getType, rrs.getResourceRecords.asScala.toList.map(_.getValue))
  }

  def getHostedZone(domain: String)(implicit route53: AmazonRoute53): Either[Failure, String] = {
    for {
      hostedZones <- PaginatedAWSRequest.run(route53.listHostedZones)(_.getHostedZones)(new ListHostedZonesRequest)
      hostedZone <- findMatchingZone(hostedZones, s"${domain.stripSuffix(".")}.")
    } yield hostedZone.getId
  }

  private def findMatchingZone(hostedZones: List[HostedZone], domain: String): Either[Failure, HostedZone] = {
    val candidateZone = hostedZones
      .find(z => domain == z.getName)
    Either.fromOption(
      candidateZone,
      ResourceMissingFailure(s"No hosted zone found for $domain. Zones evaluated: ${hostedZones.map(_.getName).mkString(", ")}")
    )
  }
}
