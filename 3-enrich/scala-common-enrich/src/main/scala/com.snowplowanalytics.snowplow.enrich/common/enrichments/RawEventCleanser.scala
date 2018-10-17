package com.snowplowanalytics.snowplow.enrich.common.enrichments

import com.snowplowanalytics.snowplow.enrich.common.adapters._
import com.snowplowanalytics.snowplow.enrich.common.enrichments.RawEventCleanser._
import com.snowplowanalytics.snowplow.enrich.common.utils.ConversionUtils

trait EventAttribute {
  def getValue(event: RawEvent): Option[String]

  def updateValue(event: RawEvent, update: String): RawEvent
}

private class Parameter(val name: String) extends EventAttribute {
  override def getValue(event: RawEvent): Option[String] = event.parameters.get(name)

  override def updateValue(event: RawEvent, update: String): RawEvent =
    event.copy(parameters = event.parameters + (name -> update))
}

private class Base64Parameter(name: String) extends Parameter(name) {
  override def getValue(event: RawEvent): Option[String] = {
    val encodedValue = super.getValue(event)
    encodedValue.flatMap(ConversionUtils.decodeBase64Url(name, _).toOption)
  }

  override def updateValue(event: RawEvent, update: String): RawEvent = {
    val encodedValue = ConversionUtils.encodeBase64Url(update)
    super.updateValue(event, encodedValue)
  }
}

private class ContextReferer() extends EventAttribute {
  override def getValue(event: RawEvent): Option[String] = event.context.refererUri

  override def updateValue(event: RawEvent, update: String): RawEvent =
    event.copy(context = event.context.copy(refererUri = Some(update)))
}

object RawEventCleanser {
  type AttributeRedactor = Function1[String, Option[RedactedValue]]

  private val refererParameter         = new Parameter("refr")
  private val urlParameter             = new Parameter("url")
  private val contextReferer           = new ContextReferer
  private val contextsParameter        = new Parameter("co")
  private val encodedContextsParameter = new Base64Parameter("cx")

  private def cleanAttributes(event: RawEvent,
                              cleansings: Map[EventAttribute, AttributeRedactor]): Map[EventAttribute, RedactedValue] =
    cleansings.flatMap {
      case (attribute, cleanser) => cleanseAttribute(event, attribute, cleanser).map((attribute, _))
    }

  private def cleanseAttribute(event: RawEvent,
                               attribute: EventAttribute,
                               cleanser: AttributeRedactor): Option[RedactedValue] =
    attribute.getValue(event).flatMap(cleanser)

  private def applyRedactions(event: RawEvent, redactions: Map[EventAttribute, RedactedValue]): RawEvent =
    redactions.foldLeft(event)(applyRedaction)

  private def applyRedaction(event: RawEvent, redaction: (EventAttribute, RedactedValue)): RawEvent =
    redaction match {
      case (update, value) => update.updateValue(event, value.replacement)
    }

  def apply(): RawEventCleanser =
    new RawEventCleanser(PIIRedactor())
}

class RawEventCleanser(val redactor: PIIRedactor) {

  /**
   * Cleanses a raw event of PII in the page/referrer URLs and the contexts.
   * @param event the event to cleanse
   * @return a tuple of a clean version of the event and the set of PII types found
   */
  def cleanse(event: RawEvent): (RawEvent, Set[String]) = {
    val urlCleanser: AttributeRedactor    = redactor.cleanseUrlParameters(_, event.source.encoding)
    val stringCleanser: AttributeRedactor = redactor.cleanseString(_)

    val cleansings = Map(
      refererParameter         -> urlCleanser,
      urlParameter             -> urlCleanser,
      contextReferer           -> urlCleanser,
      contextsParameter        -> stringCleanser,
      encodedContextsParameter -> stringCleanser
    )

    val redactions = cleanAttributes(event, cleansings)

    val cleanEvent = applyRedactions(event, redactions)

    (cleanEvent, redactions.values.flatMap(_.piiType).toSet)
  }
}
