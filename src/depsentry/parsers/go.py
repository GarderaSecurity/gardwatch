import re
from pathlib import Path
from typing import AsyncIterator
from .base import DependencyParser, Dependency

class GoModParser(DependencyParser):
    def can_parse(self, file_path: Path) -> bool:
        return file_path.name == "go.mod"

    async def parse(self, file_path: Path) -> AsyncIterator[Dependency]:
        in_require_block = False
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('//'):
                    continue
                
                # Handle `require (` block start
                if line == 'require (':
                    in_require_block = True
                    continue
                
                if line == ')' and in_require_block:
                    in_require_block = False
                    continue
                
                # Extract dependency
                # Format: module/path v1.2.3
                # Or inside block: module/path v1.2.3
                
                parts = line.split()
                if not parts:
                    continue

                if parts[0] == 'require' and len(parts) >= 3 and not in_require_block:
                    # Single line require: require example.com/mod v1.0.0
                    yield Dependency(
                        name=parts[1],
                        version=parts[2],
                        source_file=str(file_path),
                        ecosystem='go'
                    )
                elif in_require_block and len(parts) >= 2:
                    # Block require: example.com/mod v1.0.0
                    yield Dependency(
                        name=parts[0],
                        version=parts[1],
                        source_file=str(file_path),
                        ecosystem='go'
                    )
