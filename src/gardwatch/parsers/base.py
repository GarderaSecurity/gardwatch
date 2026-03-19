from abc import ABC, abstractmethod
from typing import List, AsyncIterator
from pathlib import Path
from ..models import Dependency

class DependencyParser(ABC):
    @abstractmethod
    def can_parse(self, file_path: Path) -> bool:
        """Return True if this parser can handle the given file."""
        pass

    @abstractmethod
    async def parse(self, file_path: Path) -> AsyncIterator[Dependency]:
        """Parse a dependency file and yield dependencies."""
        pass
