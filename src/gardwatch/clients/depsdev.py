import httpx
import urllib.parse
import logging
from typing import Optional, Dict, Any, List
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception
from ..models import Dependency

logger = logging.getLogger(__name__)

def is_rate_limit_error(exception):
    return isinstance(exception, httpx.HTTPStatusError) and exception.response.status_code == 429

class DepsDevClient:
    BASE_URL = "https://api.deps.dev/v3alpha"

    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    def _get_system(self, ecosystem: str) -> str:
        # Map internal ecosystem names to deps.dev system names
        mapping = {
            "pypi": "pypi",
            "npm": "npm",
            "go": "go",
            "cargo": "cargo",
            "maven": "maven",
            "nuget": "nuget"
        }
        return mapping.get(ecosystem, ecosystem)

    @retry(
        retry=retry_if_exception(is_rate_limit_error),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        stop=stop_after_attempt(3),
        reraise=True
    )
    async def _make_request(self, url: str) -> Optional[httpx.Response]:
        response = await self.client.get(url)
        if response.status_code == 429:
            response.raise_for_status()
        return response

    async def get_package_and_version(self, dependency: Dependency) -> tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """
        Fetch both the general package info (with all versions) AND the specific version details.
        Returns: (package_info, version_details)
        """
        system = self._get_system(dependency.ecosystem).upper()
        name = urllib.parse.quote(dependency.name, safe='')
        
        package_info = None
        version_details = None
        target_version = dependency.version

        # 1. Fetch Package Info (contains version list)
        pkg_url = f"{self.BASE_URL}/systems/{system}/packages/{name}"
        try:
            resp = await self._make_request(pkg_url)
            if resp and resp.status_code == 200:
                package_info = resp.json()
        except httpx.HTTPError as e:
            logger.debug(f"HTTP error fetching package info for {name}: {e}")
            pass

        if not package_info:
            return None, None

        # 2. Determine target version if not provided
        if not target_version:
            for v in package_info.get("versions", []):
                if v.get("isDefault"):
                    target_version = v["versionKey"]["version"]
                    break
            if not target_version and package_info.get("versions"):
                target_version = package_info["versions"][0]["versionKey"]["version"]

        if not target_version:
            return package_info, None

        # 3. Fetch Version Details
        ver_url = f"{self.BASE_URL}/systems/{system}/packages/{name}/versions/{target_version}"
        try:
            resp = await self._make_request(ver_url)
            if resp and resp.status_code == 200:
                version_details = resp.json()
        except httpx.HTTPError as e:
            logger.debug(f"HTTP error fetching version details for {name}@{target_version}: {e}")
            pass

        # 4. Fallback: if specified version doesn't exist, try default/latest
        if not version_details and dependency.version:
            logger.info(f"Version {target_version} not found for {name}, falling back to default/latest version")
            # Find default or latest version
            fallback_version = None
            for v in package_info.get("versions", []):
                if v.get("isDefault"):
                    fallback_version = v["versionKey"]["version"]
                    break
            if not fallback_version and package_info.get("versions"):
                fallback_version = package_info["versions"][0]["versionKey"]["version"]

            if fallback_version:
                ver_url = f"{self.BASE_URL}/systems/{system}/packages/{name}/versions/{fallback_version}"
                try:
                    resp = await self._make_request(ver_url)
                    if resp and resp.status_code == 200:
                        version_details = resp.json()
                        logger.info(f"Using version {fallback_version} for {name} instead of {target_version}")
                except httpx.HTTPError as e:
                    logger.debug(f"HTTP error fetching fallback version {fallback_version}: {e}")
                    pass

        return package_info, version_details

    async def get_dependents(self, dependency: Dependency) -> Optional[int]:
        """Fetch the number of packages that depend on this version."""
        system = self._get_system(dependency.ecosystem).upper()
        name = urllib.parse.quote(dependency.name, safe='')
        version = dependency.version

        if not version:
            return None

        url = f"{self.BASE_URL}/systems/{system}/packages/{name}/versions/{version}:dependents"
        try:
            response = await self._make_request(url)
            if response and response.status_code == 200:
                data = response.json()
                return data.get("dependentCount", 0)
        except httpx.HTTPError as e:
            logger.debug(f"HTTP error fetching dependents for {name}@{version}: {e}")
            pass
        return None

    async def get_project_data(self, project_key_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch full project data (including scorecard and description) for a project.
        """
        encoded_id = urllib.parse.quote(project_key_id, safe='')
        url = f"{self.BASE_URL}/projects/{encoded_id}"

        try:
            response = await self._make_request(url)
            if not response or response.status_code != 200:
                return None
            return response.json()
        except httpx.HTTPError as e:
            logger.debug(f"HTTP error fetching project data for {project_key_id}: {e}")
            return None

    # Alias for backward compat
    get_project_scorecard = get_project_data