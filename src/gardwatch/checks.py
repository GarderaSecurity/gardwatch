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
    """Penalize young packages — older packages are more trustworthy."""
    package_age_days = 0
    if ctx.package_info and ctx.package_info.versions:
        try:
            dates = [v.publishedAt for v in ctx.package_info.versions if v.publishedAt]
            if dates:
                dates.sort()  # ISO8601 sorts lexicographically
                first_published = datetime.fromisoformat(dates[0].replace('Z', '+00:00'))
                package_age_days = (datetime.now(timezone.utc) - first_published).days
        except ValueError:
            pass

    if package_age_days < 30:
        return ScoreComponent(label="Age", score=-20, description=f"Very young package ({package_age_days} days old)", category="Trust")
    elif package_age_days < 90:
        return ScoreComponent(label="Age", score=-10, description=f"Young package ({package_age_days} days old)", category="Trust")
    elif package_age_days < 365:
        return ScoreComponent(label="Age", score=-5, description=f"Less than a year old ({package_age_days} days)", category="Trust")
    years = package_age_days // 365
    return ScoreComponent(label="Age", score=0, description=f"Mature package ({years} years)", category="Trust")

def check_downloads(ctx: CheckContext) -> Optional[ScoreComponent]:
    """Penalize packages with low download counts."""
    if ctx.dependency.ecosystem not in ["npm", "pypi", "nuget", "cargo"]:
        return None

    count = ctx.download_count
    if count is None:
        return None

    # Define thresholds based on metric (Monthly vs Total)
    if ctx.dependency.ecosystem in ["npm", "pypi"]:
        t_pop, t_low = 100_000, 200
        suffix = "last month"
    else:
        t_pop, t_low = 5_000_000, 10_000
        suffix = "total"

    if count >= t_pop:
        if count >= 1_000_000:
            val = f"{count // 1_000_000}M"
        else:
            val = f"{count // 1_000}k"
        return ScoreComponent(label="Downloads", score=0, description=f"Popular package ({val} {suffix})", category="Popularity")

    if count < t_low:
        return ScoreComponent(label="Downloads", score=-20, description=f"Very low downloads ({count:,} {suffix})", category="Popularity")

    # Between t_low and t_pop — moderate concern
    if count >= 1_000:
        val = f"{count // 1_000}k"
    else:
        val = str(count)

    return ScoreComponent(label="Downloads", score=-10, description=f"Low downloads ({val} {suffix})", category="Popularity")

def check_repository(ctx: CheckContext) -> Optional[ScoreComponent]:
    """Penalize packages without a linked source repository."""
    if not ctx.version_details:
        return None

    # Check links
    has_repo = any(link.label == "SOURCE_REPO" for link in ctx.version_details.links)

    # Fallback to related projects if links missing
    if not has_repo:
        has_repo = any(
            p.relationType == "SOURCE_REPO" for p in ctx.version_details.relatedProjects
        )

    if has_repo:
        return ScoreComponent(label="Repository", score=0, description="Source repository linked", category="Metadata")
    return ScoreComponent(label="Repository", score=-15, description="No source repository link", category="Metadata")

def check_scorecard(ctx: CheckContext) -> Optional[ScoreComponent]:
    """Penalize packages with weak or missing OpenSSF Scorecard."""
    # Try to construct scorecard link from project key
    scorecard_link = None
    if ctx.project_data and ctx.project_data.projectKey:
        project_id = ctx.project_data.projectKey.id
        if project_id and project_id.startswith("github.com/"):
            scorecard_link = f"https://securityscorecards.dev/viewer/?uri={project_id}"

    if not ctx.scorecard:
        desc = "No OpenSSF Scorecard available"
        if scorecard_link:
            desc += f" (see {scorecard_link})"
        return ScoreComponent(label="Security Score", score=-10, description=desc, category="Security")

    overall = ctx.scorecard.overallScore
    link_suffix = f" (see {scorecard_link})" if scorecard_link else ""

    if overall >= 7:
        return ScoreComponent(label="Security Score", score=0, description=f"Strong security practices ({overall}/10){link_suffix}", category="Security")
    elif overall >= 4:
        return ScoreComponent(label="Security Score", score=-5, description=f"Average security practices ({overall}/10){link_suffix}", category="Security")

    return ScoreComponent(label="Security Score", score=-15, description=f"Weak security practices ({overall}/10){link_suffix}", category="Security")

def _has_trust_signals(ctx: CheckContext) -> bool:
    """Check if a package has enough trust signals to rule out squatting."""
    # Package older than 1 year
    if ctx.package_info and ctx.package_info.versions:
        try:
            dates = [v.publishedAt for v in ctx.package_info.versions if v.publishedAt]
            if dates:
                dates.sort()
                first_published = datetime.fromisoformat(dates[0].replace('Z', '+00:00'))
                age_days = (datetime.now(timezone.utc) - first_published).days
                if age_days > 365:
                    return True
        except ValueError:
            pass

    # Has meaningful dependents
    if ctx.dependent_count is not None and ctx.dependent_count > 10:
        return True

    # Has meaningful downloads
    if ctx.download_count is not None and ctx.download_count > 10_000:
        return True

    return False


def check_typosquatting(ctx: CheckContext) -> Optional[ScoreComponent]:
    """Detect potential typosquatting of popular packages."""
    popular = TOP_PACKAGES.get(ctx.dependency.ecosystem, [])
    name = ctx.dependency.name
    if name in popular:
        return None

    matches = difflib.get_close_matches(name, popular, n=1, cutoff=0.8)
    if matches and not _has_trust_signals(ctx):
        return ScoreComponent(label="Typosquatting", score=-100, description=f"Similar to: {', '.join(matches)}", category="Threat")
    return None

def check_namespace_squatting(ctx: CheckContext) -> Optional[ScoreComponent]:
    """Detect namespace squatting patterns."""
    if _has_trust_signals(ctx):
        return None

    popular_list = TOP_PACKAGES.get(ctx.dependency.ecosystem, [])
    name = ctx.dependency.name
    for popular in popular_list:
        if popular in name and name != popular:
            if re.match(rf"^{popular}[-_]js$", name) or re.match(rf"^node[-_]{popular}$", name):
                return ScoreComponent(label="Namespace", score=-40, description=f"Potential namespace squatting of '{popular}'", category="Threat")
    return None

def check_version_spike(ctx: CheckContext) -> Optional[ScoreComponent]:
    """Detect suspicious version jumps."""
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
    return ScoreComponent(label="Versioning", score=0, description="Normal version progression", category="Threat")

def check_release_zero(ctx: CheckContext) -> Optional[ScoreComponent]:
    """Flag version 0.0.0 releases."""
    if not ctx.version_details:
        return None
    if ctx.version_details.versionKey.version in ["0.0.0", "0.0"]:
        return ScoreComponent(label="Version", score=-20, description="Package version is 0.0.0", category="Metadata")
    return ScoreComponent(label="Version", score=0, description=f"Version {ctx.version_details.versionKey.version}", category="Metadata")

def check_empty_info(ctx: CheckContext) -> Optional[ScoreComponent]:
    """Penalize missing or empty descriptions."""
    desc = ""
    if ctx.version_details and ctx.version_details.description:
        desc = ctx.version_details.description
    elif ctx.project_data and ctx.project_data.description:
        desc = ctx.project_data.description

    if not desc or len(desc.strip()) < 3:
        return ScoreComponent(label="Metadata", score=-10, description="Empty or missing description", category="Metadata")
    return ScoreComponent(label="Metadata", score=0, description="Description provided", category="Metadata")

def check_homoglyphs(ctx: CheckContext) -> Optional[ScoreComponent]:
    """Detect non-ASCII characters in package names (potential homoglyph attack)."""
    if not ctx.dependency.name.isascii():
        return ScoreComponent(label="Naming", score=-100, description="Non-ASCII characters in name (Homoglyph risk)", category="Threat")
    return None


def check_dependents(ctx: CheckContext) -> Optional[ScoreComponent]:
    """Penalize packages with few or no dependents."""
    count = ctx.dependent_count
    if count is None:
        return ScoreComponent(label="Dependents", score=-5, description="Dependent count unavailable", category="Trust")

    if count > 100:
        return ScoreComponent(label="Dependents", score=0, description=f"Well-established ({count:,} dependents)", category="Trust")
    elif count > 10:
        return ScoreComponent(label="Dependents", score=-5, description=f"Few dependents ({count:,})", category="Trust")

    return ScoreComponent(label="Dependents", score=-15, description=f"Very few dependents ({count})", category="Trust")


def check_version_count(ctx: CheckContext) -> Optional[ScoreComponent]:
    """Penalize packages with very few published versions."""
    if not ctx.package_info or not ctx.package_info.versions:
        return None

    count = len(ctx.package_info.versions)
    if count > 5:
        return ScoreComponent(label="Version History", score=0, description=f"Established release history ({count} versions)", category="Trust")
    elif count > 1:
        return ScoreComponent(label="Version History", score=-5, description=f"Few versions published ({count})", category="Trust")

    return ScoreComponent(label="Version History", score=-10, description="Only 1 version published", category="Trust")


def check_deprecated(ctx: CheckContext) -> Optional[ScoreComponent]:
    """Penalize deprecated packages."""
    if not ctx.version_details:
        return None

    if ctx.version_details.isDeprecated:
        return ScoreComponent(label="Deprecated", score=-40, description="Package version is marked as deprecated", category="Metadata")
    return ScoreComponent(label="Deprecated", score=0, description="Not deprecated", category="Metadata")


def check_maintenance(ctx: CheckContext) -> Optional[ScoreComponent]:
    """Penalize packages that haven't been updated in a long time (abandoned/unmaintained)."""
    if not ctx.package_info or not ctx.package_info.versions:
        return None

    try:
        dates = [v.publishedAt for v in ctx.package_info.versions if v.publishedAt]
        if not dates:
            return None
        dates.sort()
        latest_published = datetime.fromisoformat(dates[-1].replace('Z', '+00:00'))
        days_since_update = (datetime.now(timezone.utc) - latest_published).days
    except ValueError:
        return None

    if days_since_update > 5 * 365:
        years = days_since_update // 365
        return ScoreComponent(label="Maintenance", score=-25, description=f"No releases in {years} years", category="Trust")
    elif days_since_update > 3 * 365:
        years = days_since_update // 365
        return ScoreComponent(label="Maintenance", score=-15, description=f"No releases in {years} years", category="Trust")
    elif days_since_update > 365:
        years = days_since_update // 365
        return ScoreComponent(label="Maintenance", score=-10, description=f"No releases in {years}+ year{'s' if years > 1 else ''}", category="Trust")
    return ScoreComponent(label="Maintenance", score=0, description="Actively maintained", category="Trust")


def check_github_signals(ctx: CheckContext) -> Optional[ScoreComponent]:
    """Penalize packages with no or low GitHub community signals."""
    if not ctx.project_data or ctx.project_data.starsCount is None:
        return ScoreComponent(label="Community", score=-5, description="No GitHub project data available", category="Trust")

    stars = ctx.project_data.starsCount
    if stars >= 100:
        return ScoreComponent(label="Community", score=0, description=f"Active community ({stars:,} stars)", category="Trust")
    return ScoreComponent(label="Community", score=-5, description=f"Low community engagement ({stars} stars)", category="Trust")


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
    registry.register(check_dependents)
    registry.register(check_version_count)
    registry.register(check_deprecated)
    registry.register(check_maintenance)
    registry.register(check_github_signals)
    return registry
