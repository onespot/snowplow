package com.snowplowanalytics.snowplow.enrich.common.enrichments

import java.net.URI
import java.nio.charset.Charset
import java.util.regex.Pattern

import com.google.common.hash.Hashing
import com.netaporter.uri.Uri
import com.snowplowanalytics.snowplow.enrich.common.enrichments.PIIRedactor._
import com.snowplowanalytics.snowplow.enrich.common.utils.ConversionUtils
import org.apache.http.NameValuePair
import org.apache.http.client.utils.{URIBuilder, URLEncodedUtils}
import org.apache.http.message.BasicNameValuePair

import scala.collection.JavaConverters._
import scala.util.Try
import scala.util.control.NonFatal

case class RedactedValue(val replacement: String, val piiType: List[String])

trait PIIRule {
  def redact(value: String): RedactorResult
}

/**
 * Redacts PII matching the full string.
 * This is typically applied in a context where we suspect what kind of PII may be present.
 * @param piiType the type of PII matched by the pattern.  For example, NAME or PHONE.
 * @param valuePattern the pattern describing the PII.  If matched, the value will be redacted.
 */
class FullStringPIIDetector(val piiType: String, val valuePattern: Pattern) extends PIIRule {

  def redact(value: String): RedactorResult =
    if (!valuePattern.matcher(value).matches()) {
      Left(value)
    } else {
      Right(RedactedValue(s"** REDACTED ${piiType.toUpperCase} **", List(piiType)))
    }
}

/**
 * Redacts email addresses.
 * Since these are fairly recognizable, these can be detected anywhere within a string.
 * When redacted, a hash of the redacted value will be included with the replacement.
 * @param valuePattern the pattern to use to recognize email addresses.  Each match will be redacted.
 */
class EmailPIIDetector(val valuePattern: Pattern) extends PIIRule {

  val piiType = "EMAIL"
  val hasher  = Hashing.murmur3_128()

  def redact(value: String): RedactorResult = {
    val matcher = valuePattern.matcher(value)

    if (matcher.find) {
      val output = new StringBuffer
      do {
        matcher.appendReplacement(output, s"** REDACTED EMAIL [${generateHash(matcher.group)}] **")
      } while (matcher.find)
      matcher.appendTail(output)
      return Right(RedactedValue(output.toString, List(piiType)))
    }
    return Left(value)
  }

  private def generateHash(value: String) =
    hasher.hashString(value, Charset.forName("UTF-8")).toString
}

object PIIRedactor {

  type RedactorResult = Either[String, RedactedValue]

  private val anyNonEmptyPattern = Pattern.compile(".+")
  // Expect at least two digits to avoid false positives for common use case with 0/1 as boolean flag
  private val phonePattern = Pattern.compile("(?U:[\\d\\s()+\\-]{2,})")
  private val emailPattern = Pattern.compile(
    "(?U:\\p{Alnum}[\\p{Alnum}.!#$%&'*+/=?^_`{|}~\\-]+@\\p{Alnum}[\\p{Alnum}\\-]+(\\.[\\p{Alnum}\\-]+)+)")

  private val name: PIIRule     = new FullStringPIIDetector("NAME", anyNonEmptyPattern)
  private val account: PIIRule  = new FullStringPIIDetector("ACCOUNT", anyNonEmptyPattern)
  private val password: PIIRule = new FullStringPIIDetector("PASSWORD", anyNonEmptyPattern)
  private val phone: PIIRule    = new FullStringPIIDetector("PHONE", phonePattern)
  private val email: PIIRule    = new EmailPIIDetector(emailPattern)

  // Use lowercase keys; we fold to lowercase for parameter matching
  private val parameterValueRules: Map[String, PIIRule] = Map(
    "firstname"    -> name,
    "first-name"   -> name,
    "fname"        -> name,
    "lastname"     -> name,
    "last-name"    -> name,
    "lname"        -> name,
    "surname"      -> name,
    "name"         -> name,
    "fullname"     -> name,
    "username"     -> account,
    "user-name"    -> account,
    "user"         -> account,
    "un"           -> account,
    "password"     -> password,
    "passwd"       -> password,
    "pass"         -> password,
    "pw"           -> password,
    "tel"          -> phone,
    "tele"         -> phone,
    "telephone"    -> phone,
    "phone"        -> phone,
    "phonenum"     -> phone,
    "phonenumber"  -> phone,
    "phone-number" -> phone,
    "ph"           -> phone,
    "mob"          -> phone,
    "mobile"       -> phone
  )

  private val genericRules: List[PIIRule] = List(email)

  def apply() = new PIIRedactor(parameterValueRules, genericRules)

  private def extractParameters(uri: URI, encoding: String): Option[List[NameValuePair]] = {
    def asNameValue(value: (String, Option[String])): NameValuePair =
      new BasicNameValuePair(value._1, value._2.getOrElse(""))

    Try(URLEncodedUtils.parse(uri, encoding).asScala)
      .recoverWith {
        case NonFatal(_) => {
          Try(Uri.parse(uri.toString).query.params.map(asNameValue))
        }
      }
      .toOption
      .map(_.toList)
  }

  private def applyRedactions(parameters: List[NameValuePair],
                              redactions: Map[NameValuePair, RedactedValue]): List[NameValuePair] =
    parameters.map { parameter =>
      val redaction = redactions.get(parameter).map(_.replacement)
      redaction.map(new BasicNameValuePair(parameter.getName, _)).getOrElse(parameter)
    }

  private def replaceParameters(uri: URI, encoding: String, replacements: List[NameValuePair]): String = {
    val buffer = new URIBuilder()
      .setScheme(uri.getScheme)
      .setHost(uri.getHost)
      .setPort(uri.getPort)
      .setPath(uri.getPath)
      .setParameters(replacements.asJava)
      .setFragment(uri.getFragment)
      .setCharset(Charset.forName(encoding))

    buffer.toString
  }

  private def getRedactedPIITypes(redactions: Map[NameValuePair, RedactedValue]): List[String] =
    redactions.values.flatMap(_.piiType).toList
}

class PIIRedactor(private val parameterValueRules: Map[String, PIIRule], private val genericRules: List[PIIRule]) {

  /**
   * Redacts any query parameters of a URL which are suspected to contain PII.
   * This is driven by parameter name, providing context as to the type of PII contained.
   * For all parameters, generic redactions will also be applied, as they
   * need no context.
   *
   * @param url the url on which to perform redaction.  If this cannot be parsed, no redaction is performed.
   * @param encoding the encoding of the URL
   * @return the redaction performed.  Redactions should preserve the original structure of the input,
   *         excluding any normalization due to URL decoding/encoding roundtrip.
   */
  def cleanseUrlParameters(url: String, encoding: String): Option[RedactedValue] =
    for {
      uri        <- ConversionUtils.stringToUri(url).getOrElse(None)
      parameters <- extractParameters(uri, encoding)
      redactions <- getRedactions(parameters)
    } yield {
      val updatedParameters = applyRedactions(parameters, redactions)
      RedactedValue(replaceParameters(uri, encoding, updatedParameters), getRedactedPIITypes(redactions))
    }

  private def getRedactions(parameters: List[NameValuePair]): Option[Map[NameValuePair, RedactedValue]] = {
    val redactions = parameters.flatMap { parameter =>
      redactQueryParameter(parameter.getName, parameter.getValue).map((parameter, _))
    }
    if (redactions.isEmpty) None else Some(redactions.toMap)
  }

  private def redactQueryParameter(parameter: String, value: String): Option[RedactedValue] =
    if (value == null) {
      // Nothing to redact!
      None
    } else {
      def applyRule(rule: PIIRule): Option[RedactedValue] = rule.redact(value).right.toOption

      lookupParameterRule(parameter).flatMap(applyRule).orElse(cleanseString(value))
    }

  private def lookupParameterRule(parameter: String): Option[PIIRule] =
    parameterValueRules.get(parameter.toLowerCase)

  /**
   * Performs redaction on text.  Only generic redaction rules are applied, as
   * there is no additional context for guidance.
   * @param value the text on which to perform redaction
   * @return the redaction performed
   */
  def cleanseString(value: String): Option[RedactedValue] =
    if (value == null) {
      // Nothing to redact!
      None
    } else {
      val initialResult: RedactorResult = Left(value)
      genericRules.foldLeft(initialResult)(applyRule).right.toOption
    }

  private def applyRule(result: RedactorResult, rule: PIIRule): RedactorResult =
    result match {
      case Left(value) => rule.redact(value)
      case Right(RedactedValue(replacement, piiType)) => {
        rule.redact(replacement) match {
          case Right(RedactedValue(newReplacement, newPiiType)) =>
            Right(RedactedValue(newReplacement, piiType ++ newPiiType))
          case Left(_) => result
        }
      }
    }

}
