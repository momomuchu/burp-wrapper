"""Base class for tool namespaces."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from burp_wrapper.client import BurpClient


class BaseTools:
    """Base class providing access to the client's _call method."""

    def __init__(self, client: BurpClient):
        self._client = client

    def _call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        return self._client._call(method, params)
