"""Tests for Decoder tools."""

import json

import httpx


class TestDecoderEncode:
    def test_encode_url(self, client, mock_api):
        route = mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200, json={"result": {"result": "%3Cscript%3E", "encoding": "url"}}
            )
        )
        result = client.decoder.encode("<script>", "url")
        assert result["result"] == "%3Cscript%3E"
        body = json.loads(route.calls.last.request.content.decode())
        assert body["params"]["data"] == "<script>"
        assert body["params"]["encoding"] == "url"

    def test_encode_base64(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200, json={"result": {"result": "dGVzdA==", "encoding": "base64"}}
            )
        )
        result = client.decoder.encode("test", "base64")
        assert result["result"] == "dGVzdA=="


class TestDecoderDecode:
    def test_decode_with_encoding(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={"result": {"result": "<script>", "encoding_detected": "url", "success": True}},
            )
        )
        result = client.decoder.decode("%3Cscript%3E", encoding="url")
        assert result["result"] == "<script>"
        assert result["success"] is True

    def test_decode_auto_detect(self, client, mock_api):
        route = mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={"result": {"result": "test", "encoding_detected": "base64", "success": True}},
            )
        )
        client.decoder.decode("dGVzdA==")
        body = json.loads(route.calls.last.request.content.decode())
        assert "encoding" not in body["params"] or body["params"]["encoding"] is None


class TestDecoderSmartDecode:
    def test_smart_decode_multi_layer(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "final_result": "<script>alert(1)</script>",
                        "iterations": 2,
                        "steps": [
                            {"input": "JTNDc2NyaXB0...", "encoding_detected": "base64", "output": "%3Cscript%3E..."},
                            {"input": "%3Cscript%3E...", "encoding_detected": "url", "output": "<script>alert(1)</script>"},
                        ],
                    }
                },
            )
        )
        result = client.decoder.smart_decode("JTNDc2NyaXB0...")
        assert result["iterations"] == 2
        assert len(result["steps"]) == 2


class TestDecoderHash:
    def test_hash_sha256(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={"result": {"hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "algorithm": "sha256"}},
            )
        )
        result = client.decoder.hash("test", "sha256")
        assert result["algorithm"] == "sha256"
        assert len(result["hash"]) == 64

    def test_hash_all(self, client, mock_api):
        mock_api.post("/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "result": {
                        "md5": "098f6bcd4621d373cade4e832627b4f6",
                        "sha1": "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
                        "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                        "sha384": "...",
                        "sha512": "...",
                    }
                },
            )
        )
        result = client.decoder.hash_all("test")
        assert "md5" in result
        assert "sha256" in result
        assert "sha512" in result
