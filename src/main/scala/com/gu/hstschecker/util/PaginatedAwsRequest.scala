package com.gu.hstschecker.util

import com.amazonaws.{AmazonWebServiceRequest, AmazonWebServiceResult}
import com.amazonaws.services.route53.model.{ListHostedZonesRequest, ListHostedZonesResult, ListResourceRecordSetsRequest, ListResourceRecordSetsResult}

import scala.collection.JavaConverters._
import cats.syntax.either._

trait Paging[Request, Result, A] {
  def getPageMarker(result: Result): Option[A]
  def withPageMarker(request: Request, marker: Option[A]): Request
}

object Paging {
  def instance[Request, Result, A](
                                 get: Result => Option[A],
                                 set: Request => Option[A] => Request
                               ): Paging[Request, Result, A] = new Paging[Request, Result, A] {
    override def getPageMarker(result: Result): Option[A] = get(result)
    override def withPageMarker(request: Request, marker: Option[A]): Request =
      set(request)(marker)
  }

  implicit def listZonesMarking: Paging[ListHostedZonesRequest, ListHostedZonesResult, String] =
    Paging.instance(r => Option(r.getMarker), r => m => r.withMarker(m.orNull))


  case class ListResourceRecordSetMarker(recordName: String, recordType: String, recordIdentifier: String)

  implicit def listResourceRecordSets: Paging[ListResourceRecordSetsRequest, ListResourceRecordSetsResult, ListResourceRecordSetMarker] = {
    val resultToMaybeMarker: ListResourceRecordSetsResult => Option[ListResourceRecordSetMarker] = result => {
      if (result.isTruncated) {
        Some(ListResourceRecordSetMarker(result.getNextRecordName, result.getNextRecordType, result.getNextRecordIdentifier))
      } else {
        None
      }
    }
    Paging.instance(resultToMaybeMarker, request => marker => {
      request
        .withStartRecordName(marker.map(_.recordName).orNull)
        .withStartRecordType(marker.map(_.recordType).orNull)
        .withStartRecordIdentifier(marker.map(_.recordIdentifier).orNull)
    })
  }
}

object PaginatedAWSRequest {

  def run[Request <: AmazonWebServiceRequest, Result <: AmazonWebServiceResult[_], Item, A]
  (awsCall: Request => Result)(getItems: Result => java.util.List[Item])(request: Request)
  (implicit marking: Paging[Request, Result, A]): Either[Failure, List[Item]] = {

    def recurse( request: Request,
                 results: List[Item],
                 timesThrottled: Int ): Either[Failure, List[Item]] = {
      val newResultsAndMarker: Either[Failure, (List[Item], Option[A])] = Either.catchNonFatal {
        val result = awsCall(request)
        results ++ getItems(result).asScala.toList -> marking.getPageMarker(result)
      }.leftMap(e => AwsSdkFailure(e))

      newResultsAndMarker.flatMap { case (newResults, marker) =>
        marker match {
          case None | Some("") =>
            Right(newResults)

          case otherMarker =>
            recurse(marking.withPageMarker(request, otherMarker), newResults, timesThrottled)
        }
      }

    }

    recurse(request, List.empty, 0)
  }
}