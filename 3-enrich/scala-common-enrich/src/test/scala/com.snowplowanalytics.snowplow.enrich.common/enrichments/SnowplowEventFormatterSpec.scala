/*
 * Copyright (c) 2012-2018 Snowplow Analytics Ltd. All rights reserved.
 *
 * This program is licensed to you under the Apache License Version 2.0,
 * and you may not use this file except in compliance with the Apache License Version 2.0.
 * You may obtain a copy of the Apache License Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Apache License Version 2.0 is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Apache License Version 2.0 for the specific language governing permissions and limitations there under.
 */
package com.snowplowanalytics.snowplow.enrich.common.enrichments

import com.snowplowanalytics.snowplow.enrich.common.outputs.EnrichedEvent
import org.scalacheck.Arbitrary

// Specs2
import org.specs2.matcher.DataTables
import org.specs2.scalaz.ValidationMatchers
import org.specs2.{ScalaCheck, Specification}

class SnowplowEventFormatterSpec extends Specification with DataTables with ValidationMatchers with ScalaCheck {
  def is = s2"""
  Always includes parent context                                                                                 $p1
  Copies client context if present                                                                               $e2
  """

  def idStringGen = EventEnrichments.generateEventId()

  implicit def idStrings: Arbitrary[String] = Arbitrary(idStringGen)

  val p1 = prop((id: String) => {
    val event    = makeEvent(id)
    val contexts = SnowplowEventFormatter.generateContexts(event)
    val expected =
      s"""{"schema":"iglu:com.snowplowanalytics.snowplow/contexts/jsonschema/1-0-1","data":[{"schema":"iglu:com.snowplowanalytics.snowplow/parent_event/jsonschema/1-0-0","data":{"parentEventId":"${id}"}}]}"""
    contexts mustEqual expected
  })

  def testId = "dummyId"
  def parentEventContext =
    "{\"schema\":\"iglu:com.snowplowanalytics.snowplow/parent_event/jsonschema/1-0-0\",\"data\":{\"parentEventId\":\"dummyId\"}}"

  def userContext =
    "{\"schema\":\"iglu:com.onespot/user-id/jsonschema/1-0-0\",\"data\":{\"source\":\"email\",\"user_id\":\"3458\"}}"

  def clientContext =
    "{\"schema\":\"iglu:com.onespot/client/jsonschema/1-0-0\",\"data\":{\"company_id\":57,\"site_id\":72}}"

  def futureClientContext =
    "{\"schema\":\"iglu:com.onespot/client/jsonschema/9-8-7\",\"data\":{\"company_id\":57,\"site_id\":72,\"elephants\":false}}"

  // Should find client context if present
  def e2 =
    "SPEC NAME"           || "Event contexts" | "Output contexts" |
      "Invalid json "     !! "bad { json }" ! contexts(parentEventContext) |
      "No schema present" !! "{ \"noschema\": 1 }" ! contexts(parentEventContext) |
      "Wrong root schema" !! "{ \"schema\": \"foo\" }" ! contexts(parentEventContext) |
      "No data field"     !! "{ \"schema\": \"iglu:com.snowplowanalytics.snowplow/contexts/jsonschema/1-0-1\" }" ! contexts(
        parentEventContext) |
      "Wrong data type" !! "{ \"schema\": \"iglu:com.snowplowanalytics.snowplow/contexts/jsonschema/1-0-1\", \"data\": 1 }" ! contexts(
        parentEventContext)   |
      "No client context"     !! contexts(userContext) ! contexts(parentEventContext) |
      "Client context copied" !! contexts(s"$clientContext,$userContext") ! contexts(
        s"$parentEventContext,$clientContext") |
      "Client context version ignored" !! contexts(s"$futureClientContext,$userContext") ! contexts(
        s"$parentEventContext,$futureClientContext") |
      "Old contexts schema supported" !! contexts(s"$userContext,$clientContext", 0) ! contexts(
        s"$parentEventContext,$clientContext") |> { (_, input, output) =>
      {
        val event    = makeEvent(testId, input)
        val contexts = SnowplowEventFormatter.generateContexts(event)
        contexts mustEqual output
      }
    }

  def makeEvent(id: String, contexts: String = ""): EnrichedEvent = {
    val event = new EnrichedEvent
    event.event_id = id
    event.contexts = contexts
    event
  }

  def contexts(contexts: String, contextSchemaVersion: Int = 1): String =
    s"""{"schema":"iglu:com.snowplowanalytics.snowplow/contexts/jsonschema/1-0-$contextSchemaVersion","data":[$contexts]}"""
}
