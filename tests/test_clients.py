import pytest
from unittest.mock import AsyncMock, Mock
import httpx
from gardwatch.clients.pypi import PyPIClient
from gardwatch.clients.nuget import NugetClient
from gardwatch.clients.cargo import CargoClient

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
    mock_client.get.assert_called_with("https://crates.io/api/v1/crates/serde", headers={"User-Agent": "gardwatch-cli (bot)"}, timeout=5.0)


def _depsdev_package(default_version: str) -> dict:
    return {
        "packageKey": {"system": "NPM", "name": "@forge/cli"},
        "versions": [
            {"versionKey": {"system": "NPM", "name": "@forge/cli", "version": "14.1.0"}, "isDefault": False},
            {"versionKey": {"system": "NPM", "name": "@forge/cli", "version": default_version}, "isDefault": True},
        ],
    }


def _depsdev_version(version: str) -> dict:
    return {"versionKey": {"system": "NPM", "name": "@forge/cli", "version": version}}


@pytest.mark.anyio
async def test_depsdev_resolves_npm_dist_tag_to_default_version(mock_client):
    """`npm install pkg@latest` hands us the tag, not a version. deps.dev only
    knows versions, so the tag must resolve to the package default instead of
    reading as "package not found"."""
    from gardwatch.clients.depsdev import DepsDevClient
    from gardwatch.models import Dependency

    responses = {
        "https://api.deps.dev/v3alpha/systems/NPM/packages/%40forge%2Fcli": _depsdev_package("14.2.0"),
        "https://api.deps.dev/v3alpha/systems/NPM/packages/%40forge%2Fcli/versions/14.2.0": _depsdev_version("14.2.0"),
    }

    async def get(url, **_):
        if url in responses:
            return Mock(status_code=200, json=lambda u=url: responses[u])
        return Mock(status_code=404, json=lambda: {})

    mock_client.get = AsyncMock(side_effect=get)
    client = DepsDevClient(mock_client)

    package_info, version_details = await client.get_package_and_version(
        Dependency(name="@forge/cli", version="latest", ecosystem="npm")
    )

    assert package_info is not None
    assert version_details["versionKey"]["version"] == "14.2.0"
    requested = [call.args[0] for call in mock_client.get.call_args_list]
    assert not any(url.endswith("/versions/latest") for url in requested)


@pytest.mark.anyio
async def test_depsdev_fetches_a_known_version_as_given(mock_client):
    from gardwatch.clients.depsdev import DepsDevClient
    from gardwatch.models import Dependency

    responses = {
        "https://api.deps.dev/v3alpha/systems/NPM/packages/%40forge%2Fcli": _depsdev_package("14.2.0"),
        "https://api.deps.dev/v3alpha/systems/NPM/packages/%40forge%2Fcli/versions/14.1.0": _depsdev_version("14.1.0"),
    }

    async def get(url, **_):
        if url in responses:
            return Mock(status_code=200, json=lambda u=url: responses[u])
        return Mock(status_code=404, json=lambda: {})

    mock_client.get = AsyncMock(side_effect=get)
    client = DepsDevClient(mock_client)

    _, version_details = await client.get_package_and_version(
        Dependency(name="@forge/cli", version="14.1.0", ecosystem="npm")
    )

    assert version_details["versionKey"]["version"] == "14.1.0"
