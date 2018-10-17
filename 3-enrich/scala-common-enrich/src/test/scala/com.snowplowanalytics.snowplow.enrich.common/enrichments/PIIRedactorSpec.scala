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

import java.util.regex.Pattern

// Specs2
import org.specs2.matcher.DataTables
import org.specs2.scalaz.ValidationMatchers
import org.specs2.{ScalaCheck, Specification}

class PIIRedactorSpec extends Specification with DataTables with ValidationMatchers with ScalaCheck {
  def is = s2"""
  This is a specification to test the PIICleanser
  Invalid URL is left unchanged                                                                              $e1
  URL unchanged if no matching query parameters                                                              $e2
  Redacts values from matching query parameters                                                              $e3
  Value unchanged if no matches                                                                              $e4
  Matching substrings redacted                                                                               $e5
  """

  val badURL = "http:test.com"

  val encoding = "UTF-8"

  val fooPII   = new FullStringPIIDetector("FOO", Pattern.compile("A.*A"))
  val barPII   = new FullStringPIIDetector("BAR", Pattern.compile("B.*B"))
  val emailPII = new EmailPIIDetector(Pattern.compile("\\w+@\\w+"))

  val redactor = new PIIRedactor(Map("foo" -> fooPII, "bar" -> barPII), List(emailPII))

  def e1 = redactor.cleanseUrlParameters(badURL, encoding) must beNone

  def e2 =
    "SPEC NAME"                              || "URL" |
      "No matching parameter preserves URL"  !! "http://test.com/test?foobar=AA" |
      "Value not matching preserves URL"     !! "http://test.com/test?foo=BB" |
      "No value for parameter preserves URL" !! "http://test.com/test?foo" |> { (_, input) =>
      {
        redactor.cleanseUrlParameters(input, encoding) must beNone
      }
    }

  def e3 =
    "SPEC NAME"              || "URL"                                | "REDACTED_URL" | "REDACTED_PII" |
      "Match replaces value" !! "http://test.com/test?foo=AA&baz=BB" ! "http://test.com/test?foo=**+REDACTED+FOO+**&baz=BB" ! List(
        "FOO") |
      "Parameter match is case-insensitive" !! "http://test.com/test?FoO=AA&baz=BB" ! "http://test.com/test?FoO=**+REDACTED+FOO+**&baz=BB" ! List(
        "FOO") |
      "Multiple matching copies same param replaced" !! "http://test.com/test?foo=AA&foo=BB&foo=AZA" ! "http://test.com/test?foo=**+REDACTED+FOO+**&foo=BB&foo=**+REDACTED+FOO+**" ! List(
        "FOO",
        "FOO") |
      "Multiple matching different params replaced" !! "http://test.com/test?bar=BB&foo=AA&baz=BB" ! "http://test.com/test?bar=**+REDACTED+BAR+**&foo=**+REDACTED+FOO+**&baz=BB" ! List(
        "BAR",
        "FOO") |
      "Generic rules applied to query parameters" !! "http://test.com/test?foo=X@Y&baz=BB" ! "http://test.com/test?foo=**+REDACTED+EMAIL+%5B03e4ff391b3302dcddcc25f86ae43170%5D+**&baz=BB" ! List(
        "EMAIL") |
      "Generic rules applied to all query parameters" !! "http://test.com/test?foo=X@Y&baz=B+X@Y+B" ! "http://test.com/test?foo=**+REDACTED+EMAIL+%5B03e4ff391b3302dcddcc25f86ae43170%5D+**&baz=B+**+REDACTED+EMAIL+%5B03e4ff391b3302dcddcc25f86ae43170%5D+**+B" ! List(
        "EMAIL",
        "EMAIL") |> { (_, input, redactedUrl, redactedPii) =>
      {
        redactor.cleanseUrlParameters(input, encoding) must beSome(RedactedValue(redactedUrl, redactedPii))
      }
    }

  def e4 = redactor.cleanseString("no email match") must beNone

  def e5 =
    "SPEC NAME"                     || "VALUE"                     | "REDACTED VALUE" |
      "Matches full string"         !! "abc@xyz"                   ! "** REDACTED EMAIL [fd48cb4c4ccb8506a014f110a28b941f] **" |
      "Matches substring"           !! "Prefix abc@xyz suffix"     ! "Prefix ** REDACTED EMAIL [fd48cb4c4ccb8506a014f110a28b941f] ** suffix" |
      "Matches multiple substrings" !! "Values: abc@xyz, xyz@a123" ! "Values: ** REDACTED EMAIL [fd48cb4c4ccb8506a014f110a28b941f] **, ** REDACTED EMAIL [767c8e560c69b07ba75b4ddf0c4840cc] **" |> {
      (_, value, redactedValue) =>
        {
          redactor.cleanseString(value) must beSome(RedactedValue(redactedValue, List("EMAIL")))
        }
    }

}
