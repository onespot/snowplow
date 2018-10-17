package com.snowplowanalytics.snowplow.enrich.common.enrichments

import com.snowplowanalytics.snowplow.enrich.common.outputs.EnrichedEvent
import org.json4s.JValue
import org.json4s.JsonAST._
import org.json4s.JsonDSL._
import org.json4s.jackson.JsonMethods._

import scala.util.Try

private case class Schema(val name: String) {
  def hasSchema(obj: JValue): Boolean =
    obj \ "schema" match {
      case JString(value) => name == value
      case _              => false
    }
}

/**
 * Formats the contexts for a pii-redacted event.
 * We capture the id and, if possible, the client context of the event.
 */
object SnowplowEventFormatter {

  private val clientSchema   = Schema("iglu:com.onespot/client/jsonschema/1-0-0")
  private val contextsSchema = Schema("iglu:com.snowplowanalytics.snowplow/contexts/jsonschema/1-0-1")

  /**
   * Builds the relevant contexts for a redaction event.
   * @param event the source event which was redacted
   * @return the contexts to send with the reported redaction event
   */
  def generateContexts(event: EnrichedEvent): String = {
    val contexts = List(Some(parent(event.event_id)), clientContext(event)).flatten
    val contextJson =
      ("schema" -> contextsSchema.name) ~
        ("data" -> JArray(contexts))
    compact(render(contextJson))
  }

  private def parent(eventId: String): JValue =
    ("schema" -> "iglu:com.snowplowanalytics.snowplow/parent_event/jsonschema/1-0-0") ~
      ("data" -> ("parentEventId" -> eventId))

  private def clientContext(event: EnrichedEvent): Option[JValue] =
    for {
      wrapper <- Try(parse(event.contexts)).filter(contextsSchema.hasSchema).toOption
    } yield {
      val contexts = wrapper \ "data"
      contexts.find(clientSchema.hasSchema)
    }
}
