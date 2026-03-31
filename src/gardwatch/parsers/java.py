from defusedxml import ElementTree as ET
from pathlib import Path
from typing import AsyncIterator
from .base import DependencyParser, Dependency

class MavenPomParser(DependencyParser):
    def can_parse(self, file_path: Path) -> bool:
        return file_path.name == "pom.xml"

    async def parse(self, file_path: Path) -> AsyncIterator[Dependency]:
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
        except ET.ParseError:
            return

        # Handle namespaces: {http://maven.apache.org/POM/4.0.0}project
        # We'll just strip namespaces for simplicity or use logic to find tags ending in name
        
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"

        # Find dependencies
        # <dependencies><dependency>...</dependency></dependencies>
        
        # We need to find the 'dependencies' tag first
        deps_tag = root.find(f"{ns}dependencies")
        if deps_tag is None:
            return

        for dep in deps_tag.findall(f"{ns}dependency"):
            group_id = dep.find(f"{ns}groupId")
            artifact_id = dep.find(f"{ns}artifactId")
            version = dep.find(f"{ns}version")

            if group_id is not None and artifact_id is not None:
                g = group_id.text
                a = artifact_id.text
                v = version.text if version is not None else None
                
                # Maven coordinates: group:artifact
                full_name = f"{g}:{a}"
                
                yield Dependency(
                    name=full_name,
                    version=v,
                    source_file=str(file_path),
                    ecosystem='maven'
                )
