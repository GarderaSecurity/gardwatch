import pytest
from unittest.mock import AsyncMock, Mock
import httpx
from depsentry.clients.pypi import PyPIClient
from depsentry.clients.nuget import NugetClient
from depsentry.clients.cargo import CargoClient

@pytest.fixture
def mock_client():
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get = AsyncMock()
    return client

@pytest.mark.anyio
async def test_pypi_downloads(mock_client):
    mock_client.get.return_value = Mock(
        status_code=200,
        json=lambda: {"data": {"last_month": 12345}}
    )
    pypi = PyPIClient(mock_client)
    count = await pypi.get_download_count("requests")
    assert count == 12345
    mock_client.get.assert_called_with("https://pypistats.org/api/packages/requests/recent", timeout=5.0)

@pytest.mark.anyio
async def test_nuget_downloads(mock_client):
    mock_client.get.return_value = Mock(
        status_code=200,
        json=lambda: {"data": [{"id": "Newtonsoft.Json", "totalDownloads": 999999}]}
    )
    nuget = NugetClient(mock_client)
    count = await nuget.get_download_count("Newtonsoft.Json")
    assert count == 999999
    # The URL usually contains query params, check basic match
    args, _ = mock_client.get.call_args
    assert "api-v2v3search-0.nuget.org/query" in args[0]

@pytest.mark.anyio
async def test_cargo_downloads(mock_client):
    mock_client.get.return_value = Mock(
        status_code=200,
        json=lambda: {"crate": {"downloads": 555}}
    )
    cargo = CargoClient(mock_client)
    count = await cargo.get_download_count("serde")
    assert count == 555
    mock_client.get.assert_called_with("https://crates.io/api/v1/crates/serde", headers={"User-Agent": "depsentry-cli (bot)"}, timeout=5.0)
