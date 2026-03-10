"""Proxy tools."""

from __future__ import annotations

from typing import Any

from burp_wrapper.tools.base import BaseTools


class ProxyTools(BaseTools):
    def get_history(
        self,
        limit: int = 100,
        offset: int = 0,
        filter_host: str | None = None,
        filter_path: str | None = None,
        filter_method: str | None = None,
        filter_status: int | None = None,
        filter_mime: str | None = None,
        filter_search: str | None = None,
        in_scope_only: bool = False,
        has_params: bool | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": limit, "offset": offset, "in_scope_only": in_scope_only}
        if filter_host is not None:
            params["filter_host"] = filter_host
        if filter_path is not None:
            params["filter_path"] = filter_path
        if filter_method is not None:
            params["filter_method"] = filter_method
        if filter_status is not None:
            params["filter_status"] = filter_status
        if filter_mime is not None:
            params["filter_mime"] = filter_mime
        if filter_search is not None:
            params["filter_search"] = filter_search
        if has_params is not None:
            params["has_params"] = has_params
        return self._call("proxy.getHistory", params)

    def get_request(self, request_id: str) -> dict[str, Any]:
        return self._call("proxy.getRequest", {"request_id": request_id})

    def get_websocket_history(
        self, limit: int = 100, filter_url: str | None = None
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": limit}
        if filter_url is not None:
            params["filter_url"] = filter_url
        return self._call("proxy.getWebSocketHistory", params)

    def intercept_toggle(self, enabled: bool) -> dict[str, Any]:
        return self._call("proxy.interceptToggle", {"enabled": enabled})

    def intercept_get_message(self) -> dict[str, Any]:
        return self._call("proxy.interceptGetMessage")

    def intercept_forward(
        self, message_id: str, modified_raw: str | None = None
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"message_id": message_id}
        if modified_raw is not None:
            params["modified_raw"] = modified_raw
        return self._call("proxy.interceptForward", params)

    def intercept_drop(self, message_id: str) -> dict[str, Any]:
        return self._call("proxy.interceptDrop", {"message_id": message_id})

    def add_match_replace_rule(
        self,
        enabled: bool,
        rule_type: str,
        match: str,
        replace: str,
        is_regex: bool = False,
        comment: str = "",
    ) -> dict[str, Any]:
        return self._call(
            "proxy.addMatchReplaceRule",
            {
                "rule": {
                    "enabled": enabled,
                    "rule_type": rule_type,
                    "match": match,
                    "replace": replace,
                    "is_regex": is_regex,
                    "comment": comment,
                }
            },
        )
