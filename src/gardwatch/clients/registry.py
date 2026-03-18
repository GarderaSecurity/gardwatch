import httpx
from typing import Optional
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception

def is_rate_limit_error(exception):
    return isinstance(exception, httpx.HTTPStatusError) and exception.response.status_code == 429

class RegistryClient:
    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    @retry(
        retry=retry_if_exception(is_rate_limit_error),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        stop=stop_after_attempt(3),
        reraise=True
    )
    async def _make_request(self, url: str) -> Optional[httpx.Response]:
        response = await self.client.get(url, timeout=5.0)
        if response.status_code == 429:
            response.raise_for_status()
        return response

    async def get_pypi_download_url(self, package_name: str, version: str) -> Optional[str]:
        """Fetch the sdist (source) download URL for a PyPI package."""
        url = f"https://pypi.org/pypi/{package_name}/{version}/json"
        try:
            response = await self._make_request(url)
            if not response or response.status_code != 200:
                return None
            
            data = response.json()
            for file_info in data.get("urls", []):
                # Prefer source distribution for scanning
                if file_info.get("packagetype") == "sdist":
                    return file_info.get("url")
                # Fallback to wheel if sdist not found
                if file_info.get("packagetype") == "bdist_wheel":
                    return file_info.get("url")
        except httpx.HTTPError:
            pass
        return None

    async def get_npm_download_url(self, package_name: str, version: str) -> Optional[str]:
        """Fetch the tarball URL for an npm package."""
        # Handle scoped packages (e.g. @types/react)
        safe_name = package_name.replace("/", "%2f") if "/" in package_name else package_name
        url = f"https://registry.npmjs.org/{safe_name}/{version}"
        try:
            response = await self._make_request(url)
            if not response or response.status_code != 200:
                return None
            
            data = response.json()
            return data.get("dist", {}).get("tarball")
        except httpx.HTTPError:
            pass
        return None
