/*
 * Copyright (c) 2012-2018 Snowplow Analytics Ltd. All rights reserved.
 *
 * This program is licensed to you under the Apache License Version 2.0,
 * and you may not use this file except in compliance with the Apache License Version 2.0.
 * You may obtain a copy of the Apache License Version 2.0 at
 * http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Apache License Version 2.0 is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Apache License Version 2.0 for the specific language governing permissions and
 * limitations there under.
 */
package com.snowplowanalytics.snowplow.enrich.spark

import org.specs2.mutable.Specification

object PiiRedactionSpec {
  import EnrichJobSpec._
  val contexts =
    """eyJkYXRhIjpbeyJzY2hlbWEiOiJpZ2x1OmNvbS5zbm93cGxvd2FuYWx5dGljcy5zbm93cGxvdy9jb250ZXh0cy9qc29uc2NoZW1hLzEtMC0xIiwiZGF0YSI6W3sic2NoZW1hIjoiaWdsdTpjb20ub25lc3BvdC91c2VyLWlkL2pzb25zY2hlbWEvMS0wLTAiLCJkYXRhIjp7InNvdXJjZSI6ImVtYWlsIiwidXNlcl9pZCI6InRlc3RAYWJjLmNvbSJ9fV19LHsiZGF0YSI6eyJsb25naXR1ZGUiOjEwLCJiZWFyaW5nIjo1MCwic3BlZWQiOjE2LCJhbHRpdHVkZSI6MjAsImFsdGl0dWRlQWNjdXJhY3kiOjAuMywibGF0aXR1ZGVMb25naXR1ZGVBY2N1cmFjeSI6MC41LCJsYXRpdHVkZSI6N30sInNjaGVtYSI6ImlnbHU6Y29tLnNub3dwbG93YW5hbHl0aWNzLnNub3dwbG93L2dlb2xvY2F0aW9uX2NvbnRleHQvanNvbnNjaGVtYS8xLTAtMCJ9XSwic2NoZW1hIjoiaWdsdTpjb20uc25vd3Bsb3dhbmFseXRpY3Muc25vd3Bsb3cvY29udGV4dHMvanNvbnNjaGVtYS8xLTAtMCJ9"""

  val lines = Lines(
    s"2012-05-24  00:06:42  LHR5  3402  216.160.83.56  GET d3gs014xn8p70.cloudfront.net  /ice.png  200 http://www.psychicbazaar.com/crystals/335-howlite-tumble-stone.html?firstname=bob?novalue Mozilla/5.0%20(iPhone;%20CPU%20iPhone%20OS%205_1_1%20like%20Mac%20OS%20X)%20AppleWebKit/534.46%20(KHTML,%20like%20Gecko)%20Version/5.1%20Mobile/9B206%20Safari/7534.48.3  &e=pv&cx=$contexts&eid=550e8400-e29b-41d4-a716-446655440000&page=Psychic%20Bazaar%09Shop&dtm=1364219529188&tid=637309&vp=2560x935&ds=2543x1273&vid=41&duid=9795bd0203804cd1&p=web&tv=js-0.11.1&fp=2876815413&aid=pbzsite&lang=en-GB&cs=UTF-8&tz=Europe%2FLondon&refr=http%253A%252F%252Fwww.google.com%252Fsearch%253Fq%253Dgateway%252Boracle%252Bcards%252Bdenise%252Blinn%2526hl%253Den%2526client%253Dsafari%2526name%253Drobert&f_pdf=1&f_qt=0&f_realp=0&f_wma=0&f_dir=0&f_fla=1&f_java=1&f_gears=0&f_ag=1&res=2560x1440&cd=32&cookie=1&url=http%3A%2F%2Fwww.psychicbazaar.com%2Fcrystals%2F335-howlite-tumble-stone.html%3Ffirstname%3Dbob%26novalue&cv=clj-0.5.0-tom-0.0.4"
  )
  val expected = List(
    "pbzsite",
    "web",
    etlTimestamp,
    "2012-05-24 00:06:42.000",
    "2013-03-25 13:52:09.188",
    "page_view",
    "550e8400-e29b-41d4-a716-446655440000", // event_id is present in the querystring
    "637309",
    null, // No tracker namespace
    "js-0.11.1",
    "clj-0.5.0-tom-0.0.4",
    etlVersion,
    null, // No user_id set
    "a56b2a47752ef6dac5d5c2d9cbebf2fd69fd1f36",
    "2876815413",
    "9795bd0203804cd1",
    "41",
    null, // No network_userid set
    "US", // US geolocation
    "WA",
    "Milton",
    "98354",
    "47.2513",
    "-122.3149",
    "Washington",
    "Century Link", // Using the ISP lookup service
    "Lariat Software",
    null,
    null,
    "http://www.psychicbazaar.com/crystals/335-howlite-tumble-stone.html?firstname=**+REDACTED+NAME+**&novalue",
    "Psychic Bazaar    Shop",
    "http://www.google.com/search?q=gateway+oracle+cards+denise+linn&hl=en&client=safari&name=**+REDACTED+NAME+**",
    "http",
    "www.psychicbazaar.com",
    "80",
    "/crystals/335-howlite-tumble-stone.html",
    "firstname=**+REDACTED+NAME+**&novalue",
    null,
    "http",
    "www.google.com",
    "80",
    "/search",
    "q=gateway+oracle+cards+denise+linn&hl=en&client=safari&name=**+REDACTED+NAME+**",
    null,
    "search", // Search referer
    "Google",
    "gateway oracle cards denise linn",
    null, // No marketing campaign info
    null, //
    null, //
    null, //
    null, //
    """{"data":[{"schema":"iglu:com.snowplowanalytics.snowplow/contexts/jsonschema/1-0-1","data":[{"schema":"iglu:com.onespot/user-id/jsonschema/1-0-0","data":{"source":"email","user_id":"** REDACTED EMAIL [c902dbf600dd522e5a3b226b121974c0] **"}}]},{"data":{"longitude":10,"bearing":50,"speed":16,"altitude":20,"altitudeAccuracy":0.3,"latitudeLongitudeAccuracy":0.5,"latitude":7},"schema":"iglu:com.snowplowanalytics.snowplow/geolocation_context/jsonschema/1-0-0"}],"schema":"iglu:com.snowplowanalytics.snowplow/contexts/jsonschema/1-0-0"}""", // Custom context
    null, // Structured event fields empty
    null, //
    null, //
    null, //
    null, //
    null, // Unstructured event field empty
    null, // Transaction fields empty
    null, //
    null, //
    null, //
    null, //
    null, //
    null, //
    null, //
    null, // Transaction item fields empty
    null, //
    null, //
    null, //
    null, //
    null, //
    null, // Page ping fields are empty
    null, //
    null, //
    null, //
    "Mozilla/5.0 (iPhone; CPU iPhone OS 5_1_1 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9B206 Safari/7534.48.3",
    "Mobile Safari",
    "Safari",
    "5.1",
    "Browser (mobile)",
    "WEBKIT",
    "en-GB",
    "1",
    "1",
    "1",
    "0",
    "0",
    "0",
    "0",
    "0",
    "1",
    "1",
    "32",
    "2560",
    "935",
    "iOS 5 (iPhone)",
    "iOS",
    "Apple Inc.",
    "Europe/London",
    "Mobile",
    "1",
    "2560",
    "1440",
    "UTF-8",
    "2543",
    "1273"
  )
}

/**
 * Run an event with embedded PII and validate redaction
 */
class PiiRedactionSpec extends Specification with EnrichJobSpec {
  import EnrichJobSpec._
  override def appName = "page-view-cf-lines"
  sequential
  "A job which processes a CloudFront file containing an event with PII in URLs and contexts" should {
    // Anonymize 1 IP address quartet
    runEnrichJob(PiiRedactionSpec.lines, "cloudfront", "1", true, List("geo", "isp"))

    "correctly redacts PII in URL parameters and contexts" in {
      val Some(goods) = readPartFile(dirs.output)
      goods.size must_== 1
      val actual = goods.head.split("\t").map(s => if (s.isEmpty()) null else s)
      for (idx <- PiiRedactionSpec.expected.indices) {
        actual(idx) must BeFieldEqualTo(PiiRedactionSpec.expected(idx), idx)
      }
    }

    "not write any bad rows" in {
      dirs.badRows must beEmptyDir
    }
  }
}
