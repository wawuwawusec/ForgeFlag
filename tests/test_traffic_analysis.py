from __future__ import annotations

import unittest

from forgeflag.traffic_analysis import dns_summary_from_tshark, tcp_stream_shortlist


class TrafficAnalysisTest(unittest.TestCase):
    def test_dns_summary_extracts_queries_txt_answers_and_long_labels(self) -> None:
        output = "\n".join(
            [
                "12|short.example.com|||0",
                "13|averyverylonglabelusedforcovertchannel.example.com|||3",
                "14|txt.example.com||flag{dns_txt}|0",
                "15|short.example.com|||0",
            ]
        )

        summary = dns_summary_from_tshark(output)

        self.assertEqual(summary["query_names"][0]["name"], "short.example.com")
        self.assertEqual(summary["query_names"][0]["count"], 2)
        self.assertIn("flag{dns_txt}", summary["txt_answers"])
        self.assertEqual(summary["rcode_counts"]["3"], 1)
        self.assertEqual(summary["long_query_names"], ["averyverylonglabelusedforcovertchannel.example.com"])

    def test_tcp_stream_shortlist_ranks_http_and_flag_streams(self) -> None:
        tcp_output = "\n".join(
            [
                "7|2|10.0.0.2|4444|10.0.0.3|80|HTTP|POST /upload HTTP/1.1",
                "8|3|10.0.0.2|5000|10.0.0.4|31337|TCP|PSH, ACK Len=38 flag{tcp_stream}",
                "9|1|10.0.0.2|4000|10.0.0.5|22|SSH|Encrypted packet",
            ]
        )
        http_output = "7|2|POST|example.test|/upload|curl/8"

        shortlist = tcp_stream_shortlist(
            tcp_output,
            http_requests_output=http_output,
            decoded_payloads=("flag{tcp_stream}",),
        )

        self.assertEqual(shortlist[0]["stream_id"], "2")
        self.assertIn("http_request", shortlist[0]["hints"])
        self.assertIn("POST /upload HTTP/1.1", shortlist[0]["sample"])
        self.assertEqual(shortlist[1]["stream_id"], "3")
        self.assertIn("flag_candidate", shortlist[1]["hints"])


if __name__ == "__main__":
    unittest.main()
