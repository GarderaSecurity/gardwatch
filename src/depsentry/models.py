from typing import List, Optional, Any, Dict
from pydantic import BaseModel, Field

# --- Core Domain Models ---

class Dependency(BaseModel):
    name: str
    version: Optional[str] = None
    ecosystem: str = ""
    source_file: str = ""

# --- Score/Report Models ---

class ScoreComponent(BaseModel):
    label: str
    score: int
    description: str
    category: str  # e.g., "Security", "Trust", "Threat"

class TrustReport(BaseModel):
    status: str
    score: int
    components: List[ScoreComponent]
    reason: str
    details: List[str] = Field(default_factory=list)

# --- Deps.dev API Models (Partial wrappers for validation) ---

class DepsDevVersionKey(BaseModel):
    system: str
    name: str
    version: str

class DepsDevLink(BaseModel):
    label: str
    url: str

class DepsDevAdvisoryKey(BaseModel):
    id: str

class DepsDevProjectKey(BaseModel):
    id: str

class DepsDevRelatedProject(BaseModel):
    projectKey: DepsDevProjectKey
    relationType: str

class DepsDevVersionDetails(BaseModel):
    versionKey: DepsDevVersionKey
    publishedAt: Optional[str] = None
    isDefault: bool = False
    links: List[DepsDevLink] = Field(default_factory=list)
    advisoryKeys: List[DepsDevAdvisoryKey] = Field(default_factory=list)
    relatedProjects: List[DepsDevRelatedProject] = Field(default_factory=list)
    description: Optional[str] = None

class DepsDevPackage(BaseModel):
    packageKey: Dict[str, str] = Field(default_factory=dict)
    versions: List[DepsDevVersionDetails] = Field(default_factory=list)

class OpenSSFScorecard(BaseModel):
    overallScore: float = 0.0
    # Add other fields if checks are needed in detail

class DepsDevProject(BaseModel):
    projectKey: DepsDevProjectKey
    scorecard: Optional[OpenSSFScorecard] = None
    description: Optional[str] = None

# --- Check Context ---

class CheckContext(BaseModel):
    dependency: Dependency
    package_info: Optional[DepsDevPackage] = None
    version_details: Optional[DepsDevVersionDetails] = None
    project_data: Optional[DepsDevProject] = None
    scorecard: Optional[OpenSSFScorecard] = None
    download_count: Optional[int] = None

class PackageMetadata(BaseModel):
    name: str
    version: str
    description: str
    release_date: Optional[str] = None
    created_at: Optional[str] = None
    author: str
    downloads_last_month: int
    repository_url: Optional[str] = None
    ecosystem: str