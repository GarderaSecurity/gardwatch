"""Client for the Gardera GardWatch API (authenticated via OAuth)."""
from typing import Optional

import httpx

from ..auth import AUTH_SERVER, get_valid_token
from ..models import Dependency, ScoreComponent, TrustReport

API_URL = f"{AUTH_SERVER}/api/check"
REQUEST_TIMEOUT = 60
MAX_PURLS = 5000

ECOSYSTEM_TO_PURL_TYPE = {
    "npm": "npm",
    "pypi": "pypi",
    "cargo": "cargo",
    "go": "golang",
    "maven": "maven",
    "nuget": "nuget",
}


def dependency_to_purl(dep: Dependency) -> Optional[str]:
    """Convert a Dependency to a Package URL string."""
    purl_type = ECOSYSTEM_TO_PURL_TYPE.get(dep.ecosystem)
    if not purl_type:
        return None
    if dep.version:
        return f"pkg:{purl_type}/{dep.name}@{dep.version}"
    return f"pkg:{purl_type}/{dep.name}"


def _score_to_report(score: dict) -> TrustReport:
    """Convert an API score object to a TrustReport."""
    raw = score.get("raw_score")
    trust_score = int(raw) if raw is not None else round(score.get("score", 0) * 100)

    components = []
    for c in score.get("components") or []:
        components.append(ScoreComponent(
            label=c["label"],
            score=int(c["score"]),
            description=c["description"],
            category=c.get("category", ""),
        ))

    details = []
    if score.get("error"):
        details.append(score["error"])

    return TrustReport(
        status=score.get("status", "UNKNOWN").upper(),
        score=trust_score,
        components=components,
        reason=score.get("reason") or "",
        details=details,
    )


async def check_dependencies(
    dependencies: list[Dependency],
) -> list[tuple[Dependency, TrustReport]]:
    """
    Check dependencies via the Gardera GardWatch API.
    Returns (dependency, report) pairs in the same order as input.
    Raises on auth or network failure.
    """
    token = get_valid_token()
    if not token:
        raise RuntimeError("Not authenticated. Run 'gardwatch login' first.")

    # Build PURLs, keeping a mapping back to dependencies
    purl_to_dep: dict[str, Dependency] = {}
    purls: list[str] = []
    skipped: list[Dependency] = []

    for dep in dependencies:
        purl = dependency_to_purl(dep)
        if purl:
            purls.append(purl)
            purl_to_dep[purl] = dep
        else:
            skipped.append(dep)

    if not purls:
        return []

    if len(purls) > MAX_PURLS:
        raise RuntimeError(f"Too many packages ({len(purls)}). Maximum is {MAX_PURLS}.")

    async with httpx.AsyncClient() as client:
        response = await client.post(
            API_URL,
            json={"purls": purls},
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()

    if data.get("status", "").lower() == "failure":
        raise RuntimeError(data.get("message") or "GardWatch API returned failure")

    # Map scores back to dependencies
    results: list[tuple[Dependency, TrustReport]] = []
    scores_by_purl = {s["purl"]: s for s in data.get("scores", [])}

    for purl in purls:
        dep = purl_to_dep[purl]
        score = scores_by_purl.get(purl)
        if score:
            results.append((dep, _score_to_report(score)))

    return results
