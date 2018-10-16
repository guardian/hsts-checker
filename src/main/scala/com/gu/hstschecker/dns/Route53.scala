package com.gu.hstschecker.dns

import com.amazonaws.services.route53.model.{HostedZone, ListHostedZonesRequest, ListResourceRecordSetsRequest, ResourceRecordSet}
import com.amazonaws.services.route53.AmazonRoute53
import com.gu.hstschecker.util._
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
  case class Route53Client(name: String, client: AmazonRoute53)

  def getDelegatedZones(zoneName: String, records: List[Record], verbose: Boolean)(implicit route53: List[Route53Client]): Either[Failure, List[Zone]] = {
    val delegatedZones =
      records
        .filter(_.typeName == "NS") // only NS records
        .filterNot(_.name.stripSuffix(".") == zoneName.stripSuffix(".")) // don't look at our own NS records

    delegatedZones.traverse { delegatedZone =>
      if (delegatedZone.resourceRecords.exists(_.contains("awsdns"))) {
        getZone(delegatedZone.name, verbose).leftFlatMap {
          case ResourceMissingFailure(_) => Right(DelegatedZone(delegatedZone.name, "Not in any of the AWS accounts provided"))
          case other => Left(other)
        }
      } else {
        Right(DelegatedZone(delegatedZone.name, "Not delegated to AWS"))
      }
    }
  }

  def getZone(zoneName: String, verbose: Boolean)(implicit route53: List[Route53Client]): Either[Failure, Zone] = {
    for {
      zoneId <- attemptWithMultipleClients(getHostedZone(zoneName)(_), verbose)
      records <- attemptWithMultipleClients(getZoneRecords(zoneId)(_), verbose)
      delegatedZones <- getDelegatedZones(zoneName, records, verbose)
      zone = ActualZone(records, delegatedZones)
    } yield zone
  }

  @tailrec
  def attemptWithMultipleClients[A](f: Route53Client => Either[Failure, A], verbose: Boolean)(implicit route53: List[Route53Client]): Either[Failure, A] = {
    def attachClientName(client: Route53Client) = f(client) leftMap {
      case AwsUnauthorised(t, _) => AwsUnauthorised(t, Some(client.name))
      case other => other
    }

    route53 match {
      // if this is the last client then return the result regardless
      case last :: Nil => attachClientName(last)
      case next :: tail =>
        attachClientName(next) match {
          // if successful return
          case result @ Right(_) => result
          // if an access error, fail immediately
          case unauthorised @ Left(AwsUnauthorised(_, _)) => unauthorised
          case Left(other) =>
            if (verbose) {
              System.err.println(s"Failed when executing using ${next.name} account: $other")
            }
            attemptWithMultipleClients(f, verbose)(tail)
        }

      case Nil => Left(CliOptionsFailure("No Route53 client provided"))
    }
  }

  def getZoneRecords(zoneId: String)(implicit route53: Route53Client): Either[Failure, List[Record]] = {
    for {
      awsRecords <- PaginatedAWSRequest.run(route53.client.listResourceRecordSets)(_.getResourceRecordSets)(new ListResourceRecordSetsRequest(zoneId))
      records = awsRecords.map(convertFromAwsRecordSet)
    } yield records
  }

  def convertFromAwsRecordSet(rrs: ResourceRecordSet): Record = {
    val fixedName = rrs.getName.replace("\\052", "*")
    Record(fixedName, rrs.getTTL, rrs.getType, rrs.getResourceRecords.asScala.toList.map(_.getValue))
  }

  def getHostedZone(domain: String)(implicit route53: Route53Client): Either[Failure, String] = {
    for {
      hostedZones <- PaginatedAWSRequest.run(route53.client.listHostedZones)(_.getHostedZones)(new ListHostedZonesRequest)
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
