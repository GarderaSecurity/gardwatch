from typing import List, Optional, Callable, Protocol
from datetime import datetime, timezone
import difflib
import re
from .models import CheckContext, ScoreComponent

# Top Packages Lists (Could be externalized later)
TOP_PACKAGES = {
    "pypi": ["requests", "boto3", "pandas", "numpy", "django", "flask", "urllib3", "cryptography", "pip"],
    "npm": ["react", "vue", "lodash", "express", "axios", "moment", "typescript", "chalk", "commander"]
}

class TrustCheck(Protocol):
    def __call__(self, context: CheckContext) -> Optional[ScoreComponent]: ...

class CheckRegistry:
    def __init__(self):
        self._checks: List[TrustCheck] = []

    def register(self, check: TrustCheck):
        self._checks.append(check)

    def run_all(self, context: CheckContext) -> List[ScoreComponent]:
        results = []
        for check in self._checks:
            result = check(context)
            if result:
                results.append(result)
        return results

# --- Individual Checks ---

def check_malware(ctx: CheckContext) -> Optional[ScoreComponent]:
    if not ctx.version_details:
        return None
    
    malicious_ids = [k.id for k in ctx.version_details.advisoryKeys if k.id.startswith("MAL-")]
    if malicious_ids:
        return ScoreComponent(
            label="Malware Database",
            score=-100,
            description=f"Match: {', '.join(malicious_ids)}",
            category="Security"
        )
    return ScoreComponent(
        label="Malware Database",
        score=0,
        description="No known malware found",
        category="Security"
    )

def check_age(ctx: CheckContext) -> Optional[ScoreComponent]:
    # Determine Age
    package_age_days = 0
    if ctx.package_info and ctx.package_info.versions:
        try:
            dates = [v.publishedAt for v in ctx.package_info.versions if v.publishedAt]
            if dates:
                dates.sort() # ISO8601 sorts lexicographically
                first_published = datetime.fromisoformat(dates[0].replace('Z', '+00:00'))
                package_age_days = (datetime.now(timezone.utc) - first_published).days
        except ValueError:
            pass
    
    # We set a custom attribute on context to share this "established" fact with other checks
    # Pydantic models are immutable-ish by default but we can use setattr if allowed or wrapping class
    # For now, let's recompute or rely on the score logic. 
    # Actually, let's just return the component.
    
    if package_age_days > 365:
        return ScoreComponent(label="Age", score=20, description=f"Mature package ({package_age_days // 365} years)", category="Trust")
    elif package_age_days > 90:
        return ScoreComponent(label="Age", score=10, description=f"Established package ({package_age_days} days)", category="Trust")
    
    # Penalize young packages (unless they are popular, checked in later logic or different check?)
    # The previous logic was: "Young package" penalty ONLY if not established.
    # Here we are returning 0 or positive.
    # To replicate strictly:
    if package_age_days < 30:
         return ScoreComponent(label="Age", score=-20, description=f"Young package ({package_age_days} days)", category="Trust")
    
    return ScoreComponent(label="Age", score=0, description=f"Young package ({package_age_days} days)", category="Trust")

def check_downloads(ctx: CheckContext) -> Optional[ScoreComponent]:
    if ctx.dependency.ecosystem not in ["npm", "pypi", "nuget", "cargo"]:
        return None
        
    count = ctx.download_count
    if count is None:
        return None
    
    # Define thresholds based on metric (Monthly vs Total)
    if ctx.dependency.ecosystem in ["npm", "pypi"]:
        # Monthly stats
        t_critical, t_high, t_pop, t_low = 10_000_000, 1_000_000, 100_000, 200
        suffix = "last month"
    else:
        # Total stats (NuGet, Cargo)
        t_critical, t_high, t_pop, t_low = 500_000_000, 50_000_000, 5_000_000, 10_000
        suffix = "total"

    if count > t_critical:
        val = f"{count // 1_000_000}M"
        return ScoreComponent(label="Downloads", score=30, description=f"Extremely high popularity ({val} {suffix})", category="Popularity")
    elif count > t_high:
        val = f"{count // 1_000_000}M"
        return ScoreComponent(label="Downloads", score=20, description=f"Very high popularity ({val} {suffix})", category="Popularity")
    elif count > t_pop:
        val = f"{count // 1_000}k"
        return ScoreComponent(label="Downloads", score=10, description=f"High popularity ({val} {suffix})", category="Popularity")
    
    if count < t_low:
        return ScoreComponent(label="Downloads", score=-20, description=f"Low popularity ({count} {suffix})", category="Popularity")
        
    # Neutral case: between t_low and t_pop
    if count >= 1_000_000:
        val = f"{count / 1_000_000:.1f}M"
    elif count >= 1_000:
        val = f"{count // 1_000}k"
    else:
        val = str(count)
        
    return ScoreComponent(label="Downloads", score=0, description=f"Moderate popularity ({val} {suffix})", category="Popularity")

def check_repository(ctx: CheckContext) -> Optional[ScoreComponent]:
    if not ctx.version_details:
        return None
        
    # Check links
    has_repo = any(l.label == "SOURCE_REPO" for l in ctx.version_details.links)
    
    # Fallback to related projects if links missing
    if not has_repo:
        has_repo = any(p.relationType == "SOURCE_REPO" for p in ctx.version_details.relatedProjects)

    if has_repo:
        return ScoreComponent(label="Repository", score=10, description="Source code linked", category="Metadata")
    return ScoreComponent(label="Repository", score=-10, description="No source repository link", category="Metadata")

def check_scorecard(ctx: CheckContext) -> Optional[ScoreComponent]:
    if not ctx.scorecard:
        return ScoreComponent(label="Security Score", score=0, description="No OpenSSF Scorecard available", category="Security")
        
    overall = ctx.scorecard.overallScore
    if overall >= 7:
        return ScoreComponent(label="Security Score", score=20, description=f"Strong security practices ({overall}/10)", category="Security")
    elif overall >= 4:
        return ScoreComponent(label="Security Score", score=10, description=f"Average security practices ({overall}/10)", category="Security")
    
    return ScoreComponent(label="Security Score", score=-10, description=f"Weak security practices ({overall}/10)", category="Security")

def check_typosquatting(ctx: CheckContext) -> Optional[ScoreComponent]:
    popular = TOP_PACKAGES.get(ctx.dependency.ecosystem, [])
    name = ctx.dependency.name
    if name in popular:
        return None
        
    matches = difflib.get_close_matches(name, popular, n=1, cutoff=0.8)
    if matches:
        return ScoreComponent(label="Typosquatting", score=-100, description=f"Similar to: {', '.join(matches)}", category="Threat")
    return None

def check_namespace_squatting(ctx: CheckContext) -> Optional[ScoreComponent]:
    popular_list = TOP_PACKAGES.get(ctx.dependency.ecosystem, [])
    name = ctx.dependency.name
    for popular in popular_list:
        if popular in name and name != popular:
            if re.match(rf"^{popular}[-_]js$", name) or re.match(rf"^node[-_]{popular}$", name):
                return ScoreComponent(label="Namespace", score=-40, description=f"Potential namespace squatting of '{popular}'", category="Threat")
    return None

def check_version_spike(ctx: CheckContext) -> Optional[ScoreComponent]:
    if not ctx.package_info or not ctx.version_details:
        return None
        
    current = ctx.version_details.versionKey.version
    versions = [v.versionKey.version for v in ctx.package_info.versions]
    
    try:
        def get_major(v):
            parts = re.split(r'[.-]', v)
            return int(parts[0]) if parts and parts[0].isdigit() else 0
        
        current_major = get_major(current)
        if current_major > 20: 
            other_majors = [get_major(v) for v in versions if v != current]
            if other_majors:
                max_other = max(other_majors)
                if current_major > max_other + 10:
                    return ScoreComponent(label="Versioning", score=-50, description="Suspicious version jump detected", category="Threat")
    except Exception:
        pass
    return None

def check_release_zero(ctx: CheckContext) -> Optional[ScoreComponent]:
    if not ctx.version_details:
        return None
    if ctx.version_details.versionKey.version in ["0.0.0", "0.0"]:
        return ScoreComponent(label="Version", score=-20, description="Package version is 0.0.0", category="Metadata")
    return None

def check_empty_info(ctx: CheckContext) -> Optional[ScoreComponent]:
    desc = ""
    if ctx.version_details and ctx.version_details.description:
        desc = ctx.version_details.description
    elif ctx.project_data and ctx.project_data.description:
        desc = ctx.project_data.description
        
    if not desc or len(desc.strip()) < 3:
        return ScoreComponent(label="Metadata", score=-10, description="Empty or missing description", category="Metadata")
    return None

def check_homoglyphs(ctx: CheckContext) -> Optional[ScoreComponent]:
    if not ctx.dependency.name.isascii():
        return ScoreComponent(label="Naming", score=-100, description="Non-ASCII characters in name (Homoglyph risk)", category="Threat")
    return None

# --- Registry Factory ---

def create_default_registry() -> CheckRegistry:
    registry = CheckRegistry()
    registry.register(check_malware)
    registry.register(check_age)
    registry.register(check_downloads)
    registry.register(check_repository)
    registry.register(check_scorecard)
    registry.register(check_typosquatting)
    registry.register(check_namespace_squatting)
    registry.register(check_version_spike)
    registry.register(check_release_zero)
    registry.register(check_empty_info)
    registry.register(check_homoglyphs)
    return registry
