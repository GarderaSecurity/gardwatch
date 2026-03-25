import re
from pathlib import Path
from typing import AsyncIterator
try:
    import tomllib  # Python 3.11+
except ImportError:
    import tomli as tomllib  # Fallback for older Python
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


class PyprojectTomlParser(DependencyParser):
    def can_parse(self, file_path: Path) -> bool:
        return file_path.name == "pyproject.toml"

    def _parse_version_spec(self, spec: str) -> str | None:
        """Extract version from Poetry-style version spec like '^1.2.3' or '~1.2'."""
        if not spec:
            return None
        # Remove Poetry version operators (^, ~, etc.) and constraints
        spec = spec.strip()
        # Handle common patterns: ^1.2.3, ~1.2, >=1.2.3, ==1.2.3, *
        if spec == "*":
            return None
        # Extract version number from operators
        match = re.search(r'[\d.]+', spec)
        return match.group(0) if match else None

    async def parse(self, file_path: Path) -> AsyncIterator[Dependency]:
        with open(file_path, 'rb') as f:
            data = tomllib.load(f)

        # PEP 621 style: [project.dependencies]
        if 'project' in data and 'dependencies' in data['project']:
            for dep_spec in data['project']['dependencies']:
                # Format: "package>=1.0.0" or "package[extra]>=1.0.0"
                match = re.match(r'^([A-Za-z0-9_\-\.]+)(\[.*?\])?(.*)', dep_spec)
                if match:
                    name = match.group(1)
                    version_spec = match.group(3).strip().lstrip('=<>!~')
                    yield Dependency(
                        name=name,
                        version=version_spec if version_spec else None,
                        source_file=str(file_path),
                        ecosystem='pypi'
                    )

        # Poetry style: [tool.poetry.dependencies]
        if 'tool' in data and 'poetry' in data['tool'] and 'dependencies' in data['tool']['poetry']:
            deps = data['tool']['poetry']['dependencies']
            for name, spec in deps.items():
                if name == 'python':  # Skip Python version constraint
                    continue
                # spec can be a string like "^1.2.3" or a dict like {version = "^1.2.3", optional = true}
                if isinstance(spec, str):
                    version = self._parse_version_spec(spec)
                elif isinstance(spec, dict) and 'version' in spec:
                    version = self._parse_version_spec(spec['version'])
                else:
                    version = None

                yield Dependency(
                    name=name,
                    version=version,
                    source_file=str(file_path),
                    ecosystem='pypi'
                )

        # PEP 621 optional dependencies: [project.optional-dependencies]
        if 'project' in data and 'optional-dependencies' in data['project']:
            for group_name, deps in data['project']['optional-dependencies'].items():
                for dep_spec in deps:
                    match = re.match(r'^([A-Za-z0-9_\-\.]+)(\[.*?\])?(.*)', dep_spec)
                    if match:
                        name = match.group(1)
                        version_spec = match.group(3).strip().lstrip('=<>!~')
                        yield Dependency(
                            name=name,
                            version=version_spec if version_spec else None,
                            source_file=str(file_path),
                            ecosystem='pypi'
                        )
