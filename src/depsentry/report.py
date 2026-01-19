from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class ScoreComponent:
    label: str
    score: int
    description: str
    category: str  # e.g., "Downloads", "Age", "Security"

@dataclass
class TrustReport:
    status: str
    score: int
    components: List[ScoreComponent]
    reason: str
    details: List[str] = field(default_factory=list)
