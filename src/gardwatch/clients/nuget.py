import httpx
import logging
from typing import Optional
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception

logger = logging.getLogger(__name__)

def is_rate_limit_error(exception):
    return isinstance(exception, httpx.HTTPStatusError) and exception.response.status_code == 429

class NugetClient:
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

    async def get_download_count(self, package_name: str) -> Optional[int]:
        """
        Fetch total downloads for a NuGet package.
        Note: NuGet API returns ALL-TIME downloads, not monthly.
        """
        url = f"https://api-v2v3search-0.nuget.org/query?q=packageid:{package_name}&prerelease=false"
        try:
            response = await self._make_request(url)
            if response and response.status_code == 200:
                data = response.json()
                for item in data.get("data", []):
                    if item.get("id", "").lower() == package_name.lower():
                        return item.get("totalDownloads", 0)
        except (httpx.HTTPError, ValueError) as e:
            logger.debug(f"Failed to fetch download count for {package_name}: {e}")
        return None
