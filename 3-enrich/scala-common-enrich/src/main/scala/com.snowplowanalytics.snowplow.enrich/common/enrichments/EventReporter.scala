package com.snowplowanalytics.snowplow.enrich.common.enrichments

import com.snowplowanalytics.snowplow.enrich.common.outputs.EnrichedEvent
import org.apache.http.client.utils.URIBuilder
import org.slf4j.LoggerFactory
import scalaj.http.{Http, HttpOptions}

import scala.util.control.NonFatal

trait EventReporter {

  /**
   * Reports redactions performed on an event
   * @param event the event which was redacted
   * @param piiType the type of PII that was redacted
   */
  def reportRedactedEvent(event: EnrichedEvent, piiType: String): Unit
}

/**
 * Reports redactions back to Snowplow as pii-redacted structured events.
 * These events will have at least one context pointing at the redacted event.
 * If the source event has an attached client context, this will be copied onto
 * the redaction event.
 *
 * @param collectorHost the hostname of the Snowplow collector to which to send events
 */
class SnowplowEventReporter(private val collectorHost: String) extends EventReporter {

  private val log = LoggerFactory.getLogger(this.getClass)

  override def reportRedactedEvent(event: EnrichedEvent, piiType: String): Unit = {
    val reportingUrl = generateUrl(event, piiType)
    val req          = Http(reportingUrl).option(HttpOptions.followRedirects(true))

    try {
      val response = req.asBytes
      if (!response.isSuccess) {
        log.warn(s"Non-success response code sending event (url=$reportingUrl): ${response.code}")
      }
    } catch {
      case NonFatal(e) => log.warn(s"Failed to send redaction event (url=$reportingUrl): ${e.getMessage}")
    }
  }

  private def generateUrl(event: EnrichedEvent, piiType: String): String = {
    val builder = new URIBuilder(collectorHost)
    builder.setPath("/i")
    builder.addParameter("e", "se")
    builder.addParameter("se_ca", "pii")
    builder.addParameter("se_ac", "redacted")
    builder.addParameter("se_la", piiType)

    // Event origin parameters
    builder.addParameter("aid", "pii-redactor")
    builder.addParameter("tna", "enrich")
    builder.addParameter("p", "app")

    val contexts = SnowplowEventFormatter.generateContexts(event)
    builder.addParameter("co", contexts)

    builder.toString
  }
}
