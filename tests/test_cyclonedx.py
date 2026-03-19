import pytest
from pathlib import Path
import tempfile
import shutil
from gardwatch.parsers.cyclonedx import CycloneDXParser

@pytest.fixture
def temp_dir():
    path = tempfile.mkdtemp()
    yield Path(path)
    shutil.rmtree(path)

@pytest.mark.anyio
async def test_cyclonedx_json(temp_dir):
    sbom_json = temp_dir / "sbom.json"
    sbom_json.write_text("""
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "components": [
    {
      "type": "library",
      "name": "requests",
      "version": "2.26.0",
      "purl": "pkg:pypi/requests@2.26.0"
    },
    {
      "type": "library",
      "name": "lodash",
      "version": "4.17.21",
      "purl": "pkg:npm/lodash@4.17.21"
    }
  ]
}
""")
    parser = CycloneDXParser()
    assert parser.can_parse(sbom_json)
    
    deps = []
    async for dep in parser.parse(sbom_json):
        deps.append(dep)
        
    assert len(deps) == 2
    assert any(d.name == "requests" and d.version == "2.26.0" and d.ecosystem == "pypi" for d in deps)
    assert any(d.name == "lodash" and d.version == "4.17.21" and d.ecosystem == "npm" for d in deps)

@pytest.mark.anyio
async def test_cyclonedx_xml(temp_dir):
    sbom_xml = temp_dir / "sbom.xml"
    sbom_xml.write_text("""<?xml version="1.0"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.4">
  <components>
    <component type="library">
      <name>gin</name>
      <version>v1.9.0</version>
      <purl>pkg:golang/github.com/gin-gonic/gin@v1.9.0</purl>
    </component>
    <component type="library">
      <name>commons-lang3</name>
      <version>3.12.0</version>
      <purl>pkg:maven/org.apache.commons/commons-lang3@3.12.0</purl>
    </component>
  </components>
</bom>
""")
    parser = CycloneDXParser()
    assert parser.can_parse(sbom_xml)
    
    deps = []
    async for dep in parser.parse(sbom_xml):
        deps.append(dep)
        
    assert len(deps) == 2
    # Go package
    # PURL: pkg:golang/github.com/gin-gonic/gin@v1.9.0
    # name decoded: github.com/gin-gonic/gin
    assert any(d.name == "github.com/gin-gonic/gin" and d.version == "v1.9.0" and d.ecosystem == "go" for d in deps)
    
    # Maven package
    # PURL: pkg:maven/org.apache.commons/commons-lang3@3.12.0
    # logic: if / in name, replace last / with :
    # org.apache.commons:commons-lang3
    assert any(d.name == "org.apache.commons:commons-lang3" and d.version == "3.12.0" and d.ecosystem == "maven" for d in deps)
