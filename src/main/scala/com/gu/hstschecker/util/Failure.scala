package com.gu.hstschecker.util

import java.io.{PrintWriter, StringWriter}

import com.amazonaws.AmazonServiceException

sealed trait Failure {
  def msg: String
  def cause: Option[Throwable] = None

  def toThrowable: Throwable = cause.getOrElse(new RuntimeException(msg))
}

/**
  * This type of failure has a throwable which could potentially be logged
  */
sealed trait FailureWithThrowable extends Failure {
  def throwable: Throwable
  override def cause = Some(throwable)

  // provide a default mechanism for showing the exception to a user
  override def msg: String = {
    val stringWriter = new StringWriter()
    val writer = new PrintWriter(stringWriter)
    throwable.printStackTrace(writer)

    stringWriter.toString
  }
}

case class ResourceMissingFailure(msg: String) extends Failure

case class CliOptionsFailure(msg: String) extends Failure

case class UnknownFailure(throwable: Throwable) extends FailureWithThrowable

sealed trait AwsSdkFailure extends FailureWithThrowable

object AwsSdkFailure {
  val accessDeniedErrorCodes = Set("ExpiredToken")

  def apply(throwable: Throwable): AwsSdkFailure = {
    throwable match {
      case expired: AmazonServiceException if accessDeniedErrorCodes.contains(expired.getErrorCode) => AwsUnauthorised(expired)
      case unknown => AwsSdkUnknownFailure(unknown)
    }
  }
}

case class AwsSdkUnknownFailure(throwable: Throwable) extends AwsSdkFailure

case class AwsUnauthorised(throwable: Throwable, clientName: Option[String] = None) extends AwsSdkFailure {
  override def toString: String = {
    s"AWS unauthorised${clientName.map(n => s" using '$n' account").getOrElse("")}: $throwable"
  }
}

object Failure {
  def collect[A](eithers: List[Either[Failure, A]])(recurse: A => List[Failure]): List[Failure] = {
    eithers.flatMap {
      case Left(failure) => List(failure)
      case Right(success) => recurse(success)
    }
  }
}