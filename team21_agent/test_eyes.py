"""Unit tests for Eyes' threshold logic. These tests use mocked telemetry only."""
from __future__ import annotations

import unittest
from unittest.mock import patch

import eyes


class EyesThresholdTests(unittest.TestCase):
    def test_find_status_label_from_http_codes(self):
        labels = [
            {"http_status_code": "200", "exported_job": "frontend"},
            {"http_status_code": "503", "exported_job": "checkout"},
        ]
        self.assertEqual(eyes._find_status_label(labels), "http_status_code")

    def test_error_rate_breach_creates_incident(self):
        names = ["http_server_duration_milliseconds_count"]
        series = [
            {"http_status_code": "200", "exported_job": "checkout"},
            {"http_status_code": "503", "exported_job": "checkout"},
            {"http_status_code": "200", "exported_job": "frontend"},
        ]

        def mock_query(expression: str):
            if "sum by (exported_job)" in expression:
                return {"result": [{"metric": {"exported_job": "checkout"}, "value": [1, "12"]}]}
            if "http_status_code=~" in expression:
                return {"result": [{"metric": {}, "value": [1, "12"]}]}
            if "sum(increase(" in expression:
                return {"result": [{"metric": {}, "value": [1, "100"]}]}
            raise AssertionError(f"Unexpected query: {expression}")

        with patch.object(eyes, "_series_labels", return_value=series), patch.object(eyes, "prometheus_query", side_effect=mock_query):
            check, incidents, _meta = eyes._detect_http_error_rate(names, 300, 0.05, 20)

        self.assertEqual(check["status"], "ok")
        self.assertGreaterEqual(check["error_rate"], 0.05)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["kind"], "http_5xx_error_rate_high")
        self.assertEqual(incidents[0]["service"], "checkout")

    def test_latency_breach_creates_incident(self):
        names = ["http_server_duration_milliseconds_bucket"]
        series = [{"exported_job": "product-catalog", "le": "100"}]
        response = {"result": [{"metric": {"exported_job": "product-catalog"}, "value": [1, "1600"]}]}
        with patch.object(eyes, "_series_labels", return_value=series), patch.object(eyes, "prometheus_query", return_value=response):
            check, incidents, _meta = eyes._detect_p95_latency(names, 300, 1000)
        self.assertEqual(check["status"], "ok")
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["kind"], "http_p95_latency_high")
        self.assertEqual(incidents[0]["service"], "product-catalog")

    def test_no_compatible_metrics_is_not_reported_as_healthy(self):
        with patch.object(eyes, "prometheus_metric_names", return_value=["container_cpu_utilization_ratio"]):
            result = eyes.detect_metric_incidents()
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["incidents"], [])
        self.assertIn("Do not interpret this as a healthy result", result["summary"])


    def test_incident_cycle_starts_targeted_investigation(self):
        incident = {
            "id": "http_5xx_rate:checkout",
            "kind": "http_5xx_error_rate_high",
            "service": "checkout",
            "severity": "warning",
        }
        detection = {"status": "ok", "incidents": [incident], "checks": {}}
        docker = {
            "status": "ok", "container_count": 1, "running_count": 1,
            "unhealthy_count": 0, "stopped_count": 0,
            "unhealthy_containers": [], "stopped_containers": [],
        }
        with patch.object(eyes, "detect_metric_incidents", return_value=detection), \
             patch.object(eyes, "collect_signal", return_value=docker), \
             patch.object(eyes, "investigate_incident", return_value={"investigation_status": "evidence_collected"}) as investigate:
            result = eyes.run_detection_cycle(0.05, 1000, 300, 20)
        self.assertEqual(result["status"], "incident_detected")
        self.assertEqual(len(result["investigations"]), 1)
        investigate.assert_called_once_with(incident, 300)

    def test_log_parser_reads_demo_document_fields(self):
        hit = {
            "_index": "otel-logs-2026-10-23",
            "_source": {
                "@timestamp": "2026-10-23T10:42:08Z",
                "body": "Product Found",
                "resource": {"service.name": "product-catalog"},
                "severity": {"text": "INFO", "number": 9},
                "traceId": "abc123",
                "spanId": "def456",
            },
        }
        row = eyes._normalise_log(hit)
        self.assertEqual(row["service"], "product-catalog")
        self.assertEqual(row["severity"], "INFO")
        self.assertEqual(row["message"], "Product Found")
        self.assertEqual(row["trace_id"], "abc123")


if __name__ == "__main__":
    unittest.main(verbosity=2)
