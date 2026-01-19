import tomllib
from pathlib import Path
from typing import AsyncIterator
from .base import DependencyParser, Dependency

class PipfileParser(DependencyParser):
    def can_parse(self, file_path: Path) -> bool:
        return file_path.name == "Pipfile"

    async def parse(self, file_path: Path) -> AsyncIterator[Dependency]:
        try:
            with open(file_path, 'rb') as f:
                data = tomllib.load(f)
            
            sections = ['packages', 'dev-packages']
            for section in sections:
                if section in data:
                    for name, version in data[section].items():
                        # Pipfile versions can be strings or dicts
                        version_str = None
                        if isinstance(version, str):
                            version_str = version.strip('*=<>!~')
                        elif isinstance(version, dict):
                            version_str = version.get('version', '').strip('*=<>!~')

                        yield Dependency(
                            name=name,
                            version=version_str if version_str else None,
                            source_file=str(file_path),
                            ecosystem='pypi'
                        )
        except Exception:
            pass
