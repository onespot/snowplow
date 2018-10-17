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

import com.snowplowanalytics.snowplow.enrich.common.adapters.RawEvent
import com.snowplowanalytics.snowplow.enrich.common.loaders.{CollectorApi, CollectorContext, CollectorSource}
import com.snowplowanalytics.snowplow.enrich.common.utils.ConversionUtils.encodeBase64Url

// Specs2
import org.specs2.matcher.DataTables
import org.specs2.scalaz.ValidationMatchers
import org.specs2.{ScalaCheck, Specification}

object RawEventCleanserSpec {

  implicit class TestEvent(event: RawEvent) {
    def withParameter(parameter: String, value: String): RawEvent =
      event.copy(parameters = event.parameters + (parameter -> value))

    def withRefererUri(refererUri: String): RawEvent =
      event.copy(context = event.context.copy(refererUri = Some(refererUri)))
  }

}

class RawEventCleanserSpec extends Specification with DataTables with ValidationMatchers with ScalaCheck {
  def is = s2"""
  Redacts PII events                                                                                 $e1
  """

  val cleanser = new RawEventCleanser(PIIRedactor())

  val testCollector                       = CollectorApi("test", "0.1.2")
  val testSource                          = CollectorSource("name", "UTF-8", None)
  val baseParameters: Map[String, String] = Map.empty
  val baseContext                         = CollectorContext(None, None, None, None, List.empty, None)

  val rawEvent = RawEvent(testCollector, baseParameters, None, testSource, baseContext)

  val testURL = "http://test.com?firstname=Albert&lastname=Aardvark&phone=123 456 7890"
  val redactedURL =
    "http://test.com?firstname=**+REDACTED+NAME+**&lastname=**+REDACTED+NAME+**&phone=**+REDACTED+PHONE+**"
  val urlRedactedPII = Set("NAME", "PHONE")

  val testContexts =
    "{\"schema\":\"iglu:com.snowplowanalytics.snowplow/contexts/jsonschema/1-0-1\",\"data\":[{\"schema\":\"iglu:com.onespot/user-id/jsonschema/1-0-0\",\"data\":{\"source\":\"email\",\"user_id\":\"test@abc.com\"}}]}"
  val redactedContexts =
    "{\"schema\":\"iglu:com.snowplowanalytics.snowplow/contexts/jsonschema/1-0-1\",\"data\":[{\"schema\":\"iglu:com.onespot/user-id/jsonschema/1-0-0\",\"data\":{\"source\":\"email\",\"user_id\":\"** REDACTED EMAIL [c902dbf600dd522e5a3b226b121974c0] **\"}}]}"
  val contextRedactedPII = Set("EMAIL")

  def e1 =
    "SPEC NAME"                          || "Source Event" | "Cleansed Event" | "PII Types" |
      "Redacts PII in referer url"       !! withParameter("refr", testURL) ! withParameter("refr", redactedURL) ! urlRedactedPII |
      "Redacts PII in page url"          !! withParameter("url", testURL) ! withParameter("url", redactedURL) ! urlRedactedPII |
      "Redacts PII in context url"       !! withContextReferer(testURL) ! withContextReferer(redactedURL) ! urlRedactedPII |
      "Redacts PII in unencoded context" !! withParameter("co", testContexts) ! withParameter("co", redactedContexts) ! contextRedactedPII |
      "Redacts PII in encoded context"   !! withBase64Parameter("cx", testContexts) ! withBase64Parameter(
        "cx",
        redactedContexts) ! contextRedactedPII |> { (_, event, cleansedEvent, redactedPiiTypes) =>
      {
        cleanser.cleanse(event) mustEqual (cleansedEvent, redactedPiiTypes)
      }
    }

  def withParameter(parameter: String, value: String): RawEvent =
    rawEvent.copy(parameters = rawEvent.parameters + (parameter -> value))

  def withBase64Parameter(parameter: String, value: String): RawEvent =
    rawEvent.copy(parameters = rawEvent.parameters + (parameter -> encodeBase64Url(value)))

  def withContextReferer(refererUri: String): RawEvent =
    rawEvent.copy(context = rawEvent.context.copy(refererUri = Some(refererUri)))
}
