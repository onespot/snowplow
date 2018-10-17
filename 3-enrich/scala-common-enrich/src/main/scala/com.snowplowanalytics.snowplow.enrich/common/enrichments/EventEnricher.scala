package com.snowplowanalytics.snowplow.enrich.common.enrichments

import com.snowplowanalytics.iglu.client.Resolver
import com.snowplowanalytics.snowplow.enrich.common.ValidatedEnrichedEvent
import com.snowplowanalytics.snowplow.enrich.common.adapters.RawEvent
import com.snowplowanalytics.snowplow.enrich.common.outputs.EnrichedEvent
import org.joda.time.DateTime

/**
 * A single-event enrichment process.
 */
trait EventEnricher {
  def enrichEvent(event: RawEvent, etlVersion: String, etlTstamp: DateTime)(
    implicit resolver: Resolver): ValidatedEnrichedEvent
}

/**
 * Performs the standard event enrichment process implemented by the EnrichmentManager
 * @param registry the configured enrichments
 */
class DefaultEventEnricher(private val registry: EnrichmentRegistry) extends EventEnricher {
  override def enrichEvent(event: RawEvent, etlVersion: String, etlTstamp: DateTime)(
    implicit resolver: Resolver): ValidatedEnrichedEvent =
    EnrichmentManager.enrichEvent(registry, etlVersion, etlTstamp, event)
}

/**
 * A wrapper for a enrichment process which performs cleansing of PII on the raw events
 * prior to enrichment and reports any redacted data if enrichment doesn't reject the event.
 * @param redactor the PII cleanser to use on raw events
 * @param enricher the enrichment process being wrapped
 * @param reporter the reporter for processing redaction events
 */
class RedactingEventEnricher(private val redactor: RawEventCleanser,
                             private val enricher: EventEnricher,
                             private val reporter: EventReporter)
    extends EventEnricher {

  override def enrichEvent(event: RawEvent, etlVersion: String, etlTstamp: DateTime)(
    implicit resolver: Resolver): ValidatedEnrichedEvent = {
    val (redactedEvent, redactedPiiTypes) = redactor.cleanse(event)
    val enrichedEvent                     = enricher.enrichEvent(redactedEvent, etlVersion, etlTstamp)

    def reportRedactedTypes(e: EnrichedEvent): Unit = redactedPiiTypes.foreach { reporter.reportRedactedEvent(e, _) }

    enrichedEvent.foreach(reportRedactedTypes)

    enrichedEvent
  }
}
