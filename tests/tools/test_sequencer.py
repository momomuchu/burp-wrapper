"""Tests for Sequencer tools."""

import json

import httpx


class TestSequencerCapture:
    def test_start_live_capture(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200, json={"result": {"capture_id": "cap-1", "status": "capturing"}}
            )
        )
        result = client.sequencer.start_live_capture(
            request_id="req-1",
            token_config={"location": "cookie", "name": "session"},
            sample_count=200,
        )
        assert result["capture_id"] == "cap-1"

    def test_capture_status(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={"result": {"status": "capturing", "samples_collected": 100, "samples_target": 200}},
            )
        )
        result = client.sequencer.capture_status("cap-1")
        assert result["samples_collected"] == 100


class TestSequencerAnalyze:
    def test_analyze_capture(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"analysis_id": "ana-1"}})
        )
        result = client.sequencer.analyze("cap-1")
        assert result["analysis_id"] == "ana-1"

    def test_analyze_manual(self, client, mock_api):
        route = mock_api.post("/mcp").mock(
            return_value=httpx.Response(200, json={"result": {"analysis_id": "ana-2"}})
        )
        client.sequencer.analyze_manual(["token1", "token2", "token3"])
        body = json.loads(route.calls.last.request.content.decode())
        assert body["params"]["tokens"] == ["token1", "token2", "token3"]

    def test_results(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "overall_result": "excellent",
                        "effective_entropy_bits": 120.5,
                        "reliability_percentage": 99.0,
                        "character_level_analysis": {
                            "character_set": "hex",
                            "character_set_size": 16,
                            "characters_analyzed": 32,
                            "significant_characters": 32,
                            "position_analysis": [],
                        },
                        "bit_level_analysis": {"bits_analyzed": 128, "significant_bits": 120, "bit_analysis": []},
                        "fips_tests": {
                            "monobit": {"passed": True, "value": 0.5},
                            "poker": {"passed": True, "value": 15.0},
                            "runs": {"passed": True, "value": 0.0},
                            "long_runs": {"passed": True, "value": 0.0},
                            "overall_passed": True,
                        },
                        "correlation_analysis": {"same_position": 0.0, "different_position": 0.0},
                        "samples_analyzed": 200,
                        "recommendation": "Token randomness is excellent",
                    }
                },
            )
        )
        result = client.sequencer.results("ana-1")
        assert result["overall_result"] == "excellent"
        assert result["fips_tests"]["overall_passed"] is True
