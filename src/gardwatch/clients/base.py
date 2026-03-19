from abc import ABC, abstractmethod
import httpx
from typing import Optional
from ..models import PackageMetadata

class BaseRegistryClient(ABC):
    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    @abstractmethod
    async def get_metadata(self, package_name: str) -> Optional[PackageMetadata]:
        pass
