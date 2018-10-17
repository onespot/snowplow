package com.snowplowanalytics.snowplow.enrich.common.enrichments

import com.snowplowanalytics.snowplow.enrich.common.outputs.EnrichedEvent
import org.apache.http.client.utils.URIBuilder
import scalaj.http.Http

import scala.util.Try

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

  override def reportRedactedEvent(event: EnrichedEvent, piiType: String): Unit = {
    val reportingUrl = generateUrl(event, piiType)
    val req          = Http(reportingUrl)
    Try(req.asBytes)
  }

  private def generateUrl(event: EnrichedEvent, piiType: String): String = {
    val builder = new URIBuilder(collectorHost)
    builder.setHost(collectorHost)
    builder.setPath("/i")
    builder.addParameter("e", "se")
    builder.addParameter("se_ca", "pii")
    builder.addParameter("se_ac", "redacted")
    builder.addParameter("se_la", piiType)

    val contexts = SnowplowEventFormatter.generateContexts(event)
    builder.addParameter("co", contexts)

    builder.toString
  }
}
