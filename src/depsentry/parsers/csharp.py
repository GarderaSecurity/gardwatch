import xml.etree.ElementTree as ET
from pathlib import Path
from typing import AsyncIterator
from .base import DependencyParser, Dependency

class CSharpProjectParser(DependencyParser):
    def can_parse(self, file_path: Path) -> bool:
        return file_path.suffix == ".csproj"

    async def parse(self, file_path: Path) -> AsyncIterator[Dependency]:
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
        except ET.ParseError:
            return

        # .csproj usually doesn't strictly enforce namespaces like POM, but handled if present
        # We look for ItemGroup -> PackageReference
        
        # Iterating all elements to find PackageReference is often easier than strict path
        for elem in root.iter():
            # Strip namespace if present for tag check
            tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            
            if tag == "PackageReference":
                name = elem.get("Include")
                version = elem.get("Version")
                
                # Sometimes Version is a child element
                if not version:
                    # Check for child element (ignoring namespace)
                    for child in elem:
                        if child.tag.endswith("Version"):
                            version = child.text
                            break

                if name:
                    yield Dependency(
                        name=name,
                        version=version,
                        source_file=str(file_path),
                        ecosystem='nuget'
                    )
