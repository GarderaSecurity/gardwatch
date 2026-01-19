import tomllib
from pathlib import Path
from typing import AsyncIterator
from .base import DependencyParser, Dependency

class CargoTomlParser(DependencyParser):
    def can_parse(self, file_path: Path) -> bool:
        return file_path.name == "Cargo.toml"

    async def parse(self, file_path: Path) -> AsyncIterator[Dependency]:
        with open(file_path, "rb") as f:
            try:
                data = tomllib.load(f)
            except tomllib.TOMLDecodeError:
                return

        # Check standard dependency sections
        sections = ["dependencies", "dev-dependencies", "build-dependencies"]
        
        for section in sections:
            deps = data.get(section, {})
            for name, spec in deps.items():
                version = None
                if isinstance(spec, str):
                    version = spec
                elif isinstance(spec, dict):
                    version = spec.get("version")
                
                if version:
                    yield Dependency(
                        name=name,
                        version=version,
                        source_file=str(file_path),
                        ecosystem='cargo'
                    )
