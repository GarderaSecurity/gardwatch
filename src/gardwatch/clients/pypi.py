import httpx
import logging
from typing import Optional
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception
from .base import BaseRegistryClient
from ..models import PackageMetadata

logger = logging.getLogger(__name__)

def is_rate_limit_error(exception):
    return isinstance(exception, httpx.HTTPStatusError) and exception.response.status_code == 429

class PyPIClient(BaseRegistryClient):
    @retry(
        retry=retry_if_exception(is_rate_limit_error),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        stop=stop_after_attempt(3),
        reraise=True
    )
    async def _make_request(self, url: str, timeout: float = 10.0) -> Optional[httpx.Response]:
        response = await self.client.get(url, timeout=timeout)
        if response.status_code == 429:
            response.raise_for_status()
        return response

    async def get_download_count(self, package_name: str) -> Optional[int]:
        url = f"https://pypistats.org/api/packages/{package_name}/recent"
        try:
            response = await self._make_request(url, timeout=5.0)
            if response and response.status_code == 200:
                data = response.json()
                return data.get("data", {}).get("last_month", 0)
        except (httpx.HTTPError, ValueError) as e:
            logger.debug(f"Failed to fetch download count for {package_name}: {e}")
        return None

    async def get_metadata(self, package_name: str) -> Optional[PackageMetadata]:
        url = f"https://pypi.org/pypi/{package_name}/json"
        try:
            response = await self._make_request(url, timeout=10.0)
            if not response or response.status_code == 404:
                return None
            
            response.raise_for_status()
            data = response.json()
            info = data.get("info", {})
            releases = data.get("releases", {})
            
            # Find the first release date
            created_at = None
            if releases:
                upload_times = []
                for rel_version in releases:
                    for upload in releases[rel_version]:
                        upload_times.append(upload.get("upload_time"))
                if upload_times:
                    created_at = min(t for t in upload_times if t)

            return PackageMetadata(
                name=package_name,
                version=info.get("version", "unknown"),
                description=info.get("summary", ""),
                release_date=None, 
                created_at=created_at,
                author=info.get("author", ""),
                downloads_last_month=0, 
                repository_url=info.get("project_urls", {}).get("Source"),
                ecosystem="pypi"
            )
        except (httpx.HTTPError, KeyError):
            return None
