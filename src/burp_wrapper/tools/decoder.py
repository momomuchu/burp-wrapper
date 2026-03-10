"""Decoder tools."""

from __future__ import annotations

from typing import Any

from burp_wrapper.tools.base import BaseTools


class DecoderTools(BaseTools):
    def encode(self, data: str, encoding: str) -> dict[str, Any]:
        return self._call("decoder.encode", {"data": data, "encoding": encoding})

    def decode(self, data: str, encoding: str | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {"data": data}
        if encoding is not None:
            params["encoding"] = encoding
        return self._call("decoder.decode", params)

    def smart_decode(self, data: str, max_iterations: int = 10) -> dict[str, Any]:
        return self._call(
            "decoder.smartDecode", {"data": data, "max_iterations": max_iterations}
        )

    def hash(self, data: str, algorithm: str) -> dict[str, Any]:
        return self._call("decoder.hash", {"data": data, "algorithm": algorithm})

    def hash_all(self, data: str) -> dict[str, Any]:
        return self._call("decoder.hashAll", {"data": data})
