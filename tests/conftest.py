import pytest
import respx

from burp_wrapper.client import BurpClient


@pytest.fixture
def mock_api():
    """Mock the Burp MCP Server API."""
    with respx.mock(base_url="http://127.0.0.1:9876") as respx_mock:
        yield respx_mock


@pytest.fixture
def client():
    """Create a BurpClient instance."""
    return BurpClient(base_url="http://127.0.0.1:9876")
