"""Core Burp Suite API client."""

from __future__ import annotations

from functools import cached_property
from typing import Any

import httpx

from burp_wrapper.tools.clickbandit import ClickbanditTools
from burp_wrapper.tools.collaborator import CollaboratorTools
from burp_wrapper.tools.comparer import ComparerTools
from burp_wrapper.tools.config import ConfigTools
from burp_wrapper.tools.dashboard import DashboardTools
from burp_wrapper.tools.decoder import DecoderTools
from burp_wrapper.tools.engagement import EngagementTools
from burp_wrapper.tools.extensions import ExtensionsTools
from burp_wrapper.tools.inspector import InspectorTools
from burp_wrapper.tools.intruder import IntruderTools
from burp_wrapper.tools.logger import LoggerTools
from burp_wrapper.tools.organizer import OrganizerTools
from burp_wrapper.tools.proxy import ProxyTools
from burp_wrapper.tools.repeater import RepeaterTools
from burp_wrapper.tools.scanner import ScannerTools
from burp_wrapper.tools.search import SearchTools
from burp_wrapper.tools.sequencer import SequencerTools
from burp_wrapper.tools.target import TargetTools


class BurpAPIError(Exception):
    """Raised when the Burp API returns an error."""


class BurpClient:
    """Client for the Burp Suite MCP Server API."""

    def __init__(self, base_url: str = "http://127.0.0.1:9876", timeout: float = 30.0):
        self.base_url = base_url
        self._http = httpx.Client(base_url=base_url, timeout=timeout)

    def _call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Send a JSON-RPC-style call to the MCP server."""
        payload = {"method": method, "params": params or {}}
        try:
            resp = self._http.post("/mcp", json=payload)
        except httpx.ConnectError as e:
            raise BurpAPIError(f"Connection failed: {e}") from e

        if resp.status_code != 200:
            raise BurpAPIError(f"HTTP {resp.status_code}: {resp.text}")

        data = resp.json()
        if "error" in data:
            msg = data["error"].get("message", str(data["error"]))
            raise BurpAPIError(msg)

        return data.get("result", {})

    # --- Tool namespaces ---

    @cached_property
    def proxy(self) -> ProxyTools:
        return ProxyTools(self)

    @cached_property
    def repeater(self) -> RepeaterTools:
        return RepeaterTools(self)

    @cached_property
    def intruder(self) -> IntruderTools:
        return IntruderTools(self)

    @cached_property
    def scanner(self) -> ScannerTools:
        return ScannerTools(self)

    @cached_property
    def decoder(self) -> DecoderTools:
        return DecoderTools(self)

    @cached_property
    def collaborator(self) -> CollaboratorTools:
        return CollaboratorTools(self)

    @cached_property
    def target(self) -> TargetTools:
        return TargetTools(self)

    @cached_property
    def sequencer(self) -> SequencerTools:
        return SequencerTools(self)

    @cached_property
    def comparer(self) -> ComparerTools:
        return ComparerTools(self)

    @cached_property
    def logger(self) -> LoggerTools:
        return LoggerTools(self)

    @cached_property
    def dashboard(self) -> DashboardTools:
        return DashboardTools(self)

    @cached_property
    def organizer(self) -> OrganizerTools:
        return OrganizerTools(self)

    @cached_property
    def search(self) -> SearchTools:
        return SearchTools(self)

    @cached_property
    def inspector(self) -> InspectorTools:
        return InspectorTools(self)

    @cached_property
    def engagement(self) -> EngagementTools:
        return EngagementTools(self)

    @cached_property
    def extensions(self) -> ExtensionsTools:
        return ExtensionsTools(self)

    @cached_property
    def config(self) -> ConfigTools:
        return ConfigTools(self)

    @cached_property
    def clickbandit(self) -> ClickbanditTools:
        return ClickbanditTools(self)
