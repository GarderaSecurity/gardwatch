import json
import xml.etree.ElementTree as ET
import defusedxml.ElementTree as DET
from pathlib import Path
from typing import AsyncIterator, Optional, Tuple
import urllib.parse
from .base import DependencyParser, Dependency

class CycloneDXParser(DependencyParser):
    def _detect_format(self, file_path: Path) -> Optional[str]:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Read enough to find the format specifiers
                head = f.read(4096)
                head_strip = head.strip()
                
                if head_strip.startswith('{') and '"bomFormat"' in head and '"CycloneDX"' in head:
                    return 'json'
                
                if '<bom' in head or 'http://cyclonedx.org/schema/bom' in head:
                    return 'xml'
        except Exception:
            pass
        return None

    def can_parse(self, file_path: Path) -> bool:
        return self._detect_format(file_path) is not None

    async def parse(self, file_path: Path) -> AsyncIterator[Dependency]:
        fmt = self._detect_format(file_path)
        if fmt == 'json':
            async for dep in self._parse_json(file_path):
                yield dep
        elif fmt == 'xml':
            async for dep in self._parse_xml(file_path):
                yield dep

    async def _parse_json(self, file_path: Path) -> AsyncIterator[Dependency]:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            for component in data.get('components', []):
                purl = component.get('purl')
                if purl:
                    dep = self._parse_purl(purl, str(file_path))
                    if dep:
                        yield dep
        except Exception:
            pass

    async def _parse_xml(self, file_path: Path) -> AsyncIterator[Dependency]:
        try:
            tree = DET.parse(file_path)
            root = tree.getroot()
            
            # XML Namespaces are annoying, ignore them for tag searching if possible
            # or handle them dynamically. CycloneDX namespaces version changes.
            # Local name strategy:
            
            # Find all 'component' tags
            for elem in root.iter():
                if elem.tag.endswith('component'):
                    purl_elem = None
                    # Search for purl child
                    for child in elem:
                        if child.tag.endswith('purl'):
                            purl_elem = child
                            break
                    
                    if purl_elem is not None and purl_elem.text:
                        dep = self._parse_purl(purl_elem.text, str(file_path))
                        if dep:
                            yield dep
        except Exception:
            pass

    def _parse_purl(self, purl: str, source_file: str) -> Optional[Dependency]:
        # Format: pkg:type/namespace/name@version?qualifiers#subpath
        if not purl.startswith('pkg:'):
            return None
            
        try:
            # Strip scheme
            remainder = purl[4:]
            
            # Split type
            if '/' not in remainder:
                return None
            parts = remainder.split('/', 1)
            pkg_type = parts[0]
            remainder = parts[1]
            
            # Split version
            version = None
            if '@' in remainder:
                name_part, ver_part = remainder.split('@', 1)
                remainder = name_part
                
                # Strip qualifiers/subpath from version
                if '?' in ver_part:
                    version = ver_part.split('?', 1)[0]
                elif '#' in ver_part:
                    version = ver_part.split('#', 1)[0]
                else:
                    version = ver_part
            
            # Strip qualifiers/subpath from name (if no version present or left over)
            if '?' in remainder:
                remainder = remainder.split('?', 1)[0]
            if '#' in remainder:
                remainder = remainder.split('#', 1)[0]
                
            name = remainder
            
            # URL decode name/namespace
            # PURL spec says namespace/name are percent-encoded.
            name = urllib.parse.unquote(name)
            
            ecosystem = self._map_type_to_ecosystem(pkg_type)
            if not ecosystem:
                return None
            
            # Special handling for maven: group:artifact
            if ecosystem == "maven" and '/' in name:
                # purl: pkg:maven/org.apache/commons-lang3
                # desired: org.apache:commons-lang3
                # PURL uses / separator for namespace, maven uses : for group:artifact
                # Wait, purl spec for maven: pkg:maven/org.apache.commons/io@1.3.2 -> group=org.apache.commons, artifact=io
                # The implementation of split above puts 'org.apache.commons/io' into 'remainder'.
                # So 'name' is 'org.apache.commons/io'.
                # We want 'org.apache.commons:io'.
                # But wait, what if namespace is missing? pkg:maven/artifact
                if '/' in name:
                     group, artifact = name.rsplit('/', 1)
                     name = f"{group}:{artifact}"

            return Dependency(
                name=name,
                version=version,
                ecosystem=ecosystem,
                source_file=source_file
            )
        except Exception:
            return None

    def _map_type_to_ecosystem(self, pkg_type: str) -> Optional[str]:
        mapping = {
            "npm": "npm",
            "pypi": "pypi",
            "golang": "go",
            "maven": "maven",
            "nuget": "nuget",
            "cargo": "cargo"
        }
        return mapping.get(pkg_type)
