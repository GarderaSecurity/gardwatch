import json
from pathlib import Path
from typing import AsyncIterator
from .base import DependencyParser, Dependency

class PackageJsonParser(DependencyParser):
    def can_parse(self, file_path: Path) -> bool:
        return file_path.name == "package.json"

    async def parse(self, file_path: Path) -> AsyncIterator[Dependency]:
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                
            sections = ['dependencies', 'devDependencies', 'peerDependencies']
            
            for section in sections:
                if section in data:
                    for name, version in data[section].items():
                        yield Dependency(
                            name=name,
                            version=version.strip('^~*'),
                            source_file=str(file_path),
                            ecosystem='npm'
                        )
        except json.JSONDecodeError:
            pass
        except Exception:
            pass
