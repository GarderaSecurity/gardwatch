import re
from pathlib import Path
from typing import AsyncIterator
from .base import DependencyParser, Dependency

class RequirementsTxtParser(DependencyParser):
    def can_parse(self, file_path: Path) -> bool:
        return file_path.name == "requirements.txt" or file_path.suffix == ".txt"

    async def parse(self, file_path: Path) -> AsyncIterator[Dependency]:
        # Simple async simulation for now as we're reading local files
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Basic parsing for requirements.txt
                match = re.match(r'^([A-Za-z0-9_\-\.]+)(.*)', line)
                if match:
                    name = match.group(1)
                    version_spec = match.group(2).strip().lstrip('=<>!~')
                    
                    yield Dependency(
                        name=name,
                        version=version_spec if version_spec else None,
                        source_file=str(file_path),
                        ecosystem='pypi'
                    )
