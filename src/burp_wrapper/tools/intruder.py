"""Intruder tools."""

from __future__ import annotations

from typing import Any

from burp_wrapper.tools.base import BaseTools


class IntruderTools(BaseTools):
    def create_attack(
        self,
        request_id: str,
        attack_type: str,
        positions: list[dict[str, Any]],
        payloads: list[dict[str, Any]],
        payload_processing: list[dict[str, Any]] | None = None,
        grep_match: list[str] | None = None,
        grep_extract: list[dict[str, Any]] | None = None,
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        config: dict[str, Any] = {
            "request_id": request_id,
            "attack_type": attack_type,
            "positions": positions,
            "payloads": payloads,
        }
        if payload_processing is not None:
            config["payload_processing"] = payload_processing
        if grep_match is not None:
            config["grep_match"] = grep_match
        if grep_extract is not None:
            config["grep_extract"] = grep_extract
        if options is not None:
            config["options"] = options
        return self._call("intruder.createAttack", {"config": config})

    def start(self, attack_id: str) -> dict[str, Any]:
        return self._call("intruder.start", {"attack_id": attack_id})

    def quick_fuzz(
        self,
        request_id: str,
        param_name: str,
        payloads: list[str],
        concurrent: int = 5,
    ) -> dict[str, Any]:
        return self._call(
            "intruder.quickFuzz",
            {
                "request_id": request_id,
                "param_name": param_name,
                "payloads": payloads,
                "concurrent": concurrent,
            },
        )

    def status(self, attack_id: str) -> dict[str, Any]:
        return self._call("intruder.status", {"attack_id": attack_id})

    def results(
        self,
        attack_id: str,
        filters: dict[str, Any] | None = None,
        limit: int = 1000,
        offset: int = 0,
        sort_by: str = "index",
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "attack_id": attack_id,
            "limit": limit,
            "offset": offset,
            "sort_by": sort_by,
        }
        if filters is not None:
            params["filters"] = filters
        return self._call("intruder.results", params)

    def pause(self, attack_id: str) -> dict[str, Any]:
        return self._call("intruder.pause", {"attack_id": attack_id})

    def resume(self, attack_id: str) -> dict[str, Any]:
        return self._call("intruder.resume", {"attack_id": attack_id})

    def stop(self, attack_id: str) -> dict[str, Any]:
        return self._call("intruder.stop", {"attack_id": attack_id})
