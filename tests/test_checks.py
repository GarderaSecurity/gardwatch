import pytest
from datetime import datetime, timedelta, timezone
from depsentry.models import (
    Dependency, CheckContext, DepsDevVersionDetails, DepsDevPackage, 
    DepsDevVersionKey, DepsDevAdvisoryKey, DepsDevLink, OpenSSFScorecard, DepsDevProject,
    DepsDevProjectKey
)
from depsentry.checks import (
    check_malware, check_typosquatting, check_namespace_squatting, 
    check_version_spike, check_release_zero, check_empty_info, 
    check_homoglyphs, check_age, check_downloads
)

@pytest.fixture
def base_context():
    return CheckContext(
        dependency=Dependency(name="test-package", ecosystem="npm", version="1.0.0"),
        version_details=DepsDevVersionDetails(
            versionKey=DepsDevVersionKey(system="NPM", name="test-package", version="1.0.0"),
            publishedAt=datetime.now(timezone.utc).isoformat(),
            description="A valid description"
        ),
        package_info=DepsDevPackage(
            versions=[
                DepsDevVersionDetails(
                    versionKey=DepsDevVersionKey(system="NPM", name="test-package", version="1.0.0"),
                    publishedAt=datetime.now(timezone.utc).isoformat()
                )
            ]
        )
    )

def test_check_malware(base_context):
    # Case 1: No malware
    assert check_malware(base_context) is None

    # Case 2: Malware present
    base_context.version_details.advisoryKeys = [DepsDevAdvisoryKey(id="MAL-2024-1234")]
    result = check_malware(base_context)
    assert result is not None
    assert result.label == "Malware Database"
    assert result.score == -100

def test_check_typosquatting(base_context):
    # Case 1: Safe name
    base_context.dependency.name = "react" # Popular package itself
    assert check_typosquatting(base_context) is None

    # Case 2: Typosquat
    base_context.dependency.name = "reeact"
    base_context.dependency.ecosystem = "npm"
    result = check_typosquatting(base_context)
    assert result is not None
    assert result.label == "Typosquatting"
    assert "react" in result.description

def test_check_namespace_squatting(base_context):
    base_context.dependency.ecosystem = "npm"
    
    # Case 1: Safe
    base_context.dependency.name = "react-dom"
    assert check_namespace_squatting(base_context) is None

    # Case 2: Squatting patterns
    base_context.dependency.name = "react-js"
    result = check_namespace_squatting(base_context)
    assert result is not None
    assert result.label == "Namespace"

    base_context.dependency.name = "node-react"
    result = check_namespace_squatting(base_context)
    assert result is not None

def test_check_version_spike(base_context):
    # Case 1: Normal versioning
    # base_context has 1.0.0, current is 1.0.0
    assert check_version_spike(base_context) is None

    # Case 2: Spike
    # History has 1.0.0, 1.1.0. Current is 99.0.0
    base_context.package_info.versions = [
        DepsDevVersionDetails(versionKey=DepsDevVersionKey(system="NPM", name="test", version="1.0.0")),
        DepsDevVersionDetails(versionKey=DepsDevVersionKey(system="NPM", name="test", version="1.1.0")),
        DepsDevVersionDetails(versionKey=DepsDevVersionKey(system="NPM", name="test", version="99.0.0")),
    ]
    base_context.version_details.versionKey.version = "99.0.0"
    
    result = check_version_spike(base_context)
    assert result is not None
    assert result.label == "Versioning"
    assert result.score == -50

def test_check_release_zero(base_context):
    base_context.version_details.versionKey.version = "0.0.0"
    result = check_release_zero(base_context)
    assert result is not None
    assert result.label == "Version"
    assert result.score == -20

def test_check_empty_info(base_context):
    # Case 1: Description present (in fixture)
    assert check_empty_info(base_context) is None

    # Case 2: Empty description
    base_context.version_details.description = ""
    # Ensure fallback project data is also empty or None
    base_context.project_data = None 
    
    result = check_empty_info(base_context)
    assert result is not None
    assert result.label == "Metadata"

    # Case 3: Fallback to project data
    base_context.project_data = DepsDevProject(
        projectKey=DepsDevProjectKey(id="github.com/test/repo"), 
        description="Valid description"
    )
    assert check_empty_info(base_context) is None

def test_check_homoglyphs(base_context):
    # Case 1: ASCII
    base_context.dependency.name = "react"
    assert check_homoglyphs(base_context) is None

    # Case 2: Homoglyph (Cyrillic 'a')
    base_context.dependency.name = "re\u0430ct" 
    result = check_homoglyphs(base_context)
    assert result is not None
    assert result.label == "Naming"
    assert result.score == -100

def test_check_age(base_context):
    # Case 1: Young package (<30 days)
    # Fixture sets publishedAt to now(), so age is 0
    result = check_age(base_context)
    assert result.score == -20 # Young package penalty
    
    # Case 2: Established package (>90 days)
    old_date = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
    base_context.package_info.versions[0].publishedAt = old_date
    result = check_age(base_context)
    assert result.score == 10
    
    # Case 3: Mature (>365)
    ancient_date = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
    base_context.package_info.versions[0].publishedAt = ancient_date
    result = check_age(base_context)
    assert result.score == 20

def test_check_downloads(base_context):
    base_context.dependency.ecosystem = "npm"
    
    # Case 1: Low downloads
    base_context.download_count = 50
    result = check_downloads(base_context)
    assert result is not None
    assert result.score == -20
    
    # Case 2: High downloads
    base_context.download_count = 2_000_000
    result = check_downloads(base_context)
    assert result.score == 20
