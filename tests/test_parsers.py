import pytest
from pathlib import Path
import tempfile
import shutil
from depsentry.parsers.go import GoModParser
from depsentry.parsers.rust import CargoTomlParser
from depsentry.parsers.java import MavenPomParser
from depsentry.parsers.csharp import CSharpProjectParser

@pytest.fixture
def temp_dir():
    path = tempfile.mkdtemp()
    yield Path(path)
    shutil.rmtree(path)

@pytest.mark.anyio
async def test_go_parser(temp_dir):
    go_mod = temp_dir / "go.mod"
    go_mod.write_text("""
module example.com/test
go 1.21
require (
    github.com/gin-gonic/gin v1.9.1
    golang.org/x/crypto v0.14.0 // indirect
)
require github.com/single/line v1.0.0
""")
    parser = GoModParser()
    deps = []
    async for dep in parser.parse(go_mod):
        deps.append(dep)
    
    assert any(d.name == "github.com/gin-gonic/gin" and d.version == "v1.9.1" for d in deps)
    assert any(d.name == "github.com/single/line" and d.version == "v1.0.0" for d in deps)

@pytest.mark.anyio
async def test_rust_parser(temp_dir):
    cargo_toml = temp_dir / "Cargo.toml"
    cargo_toml.write_text("""
[package]
name = "test"
[dependencies]
serde = "1.0"
tokio = { version = "1.28", features = ["full"] }
""")
    parser = CargoTomlParser()
    deps = []
    async for dep in parser.parse(cargo_toml):
        deps.append(dep)
    
    assert any(d.name == "serde" and d.version == "1.0" for d in deps)
    assert any(d.name == "tokio" and d.version == "1.28" for d in deps)

@pytest.mark.anyio
async def test_java_parser(temp_dir):
    pom_xml = temp_dir / "pom.xml"
    pom_xml.write_text("""
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <dependency>
            <groupId>org.slf4j</groupId>
            <artifactId>slf4j-api</artifactId>
            <version>2.0.9</version>
        </dependency>
    </dependencies>
</project>
""")
    parser = MavenPomParser()
    deps = []
    async for dep in parser.parse(pom_xml):
        deps.append(dep)
    
    assert any(d.name == "org.slf4j:slf4j-api" and d.version == "2.0.9" for d in deps)

@pytest.mark.anyio
async def test_csharp_parser(temp_dir):
    csproj = temp_dir / "test.csproj"
    csproj.write_text("""
<Project Sdk="Microsoft.NET.Sdk">
    <ItemGroup>
        <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
        <PackageReference Include="Serilog">
            <Version>3.1.1</Version>
        </PackageReference>
    </ItemGroup>
</Project>
""")
    parser = CSharpProjectParser()
    deps = []
    async for dep in parser.parse(csproj):
        deps.append(dep)
    
    assert any(d.name == "Newtonsoft.Json" and d.version == "13.0.1" for d in deps)
    assert any(d.name == "Serilog" and d.version == "3.1.1" for d in deps)
