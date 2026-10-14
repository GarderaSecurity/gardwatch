from gardwatch.engine import TrustEngine
from gardwatch.models import Dependency


def test_unresolvable_package_is_unknown_not_critical():
    """No registry data means we learned nothing. That is not evidence of
    malice, so it must not score as an alarm or accuse the user of making the
    package up."""
    report = TrustEngine().evaluate(
        Dependency(name="not-a-real-package", version=None, ecosystem="npm"),
        package_info=None,
        version_details=None,
        scorecard=None,
    )

    assert report.status == "UNKNOWN"
    assert report.score == 50
    [component] = report.components
    assert component.label == "Registry Check"
    assert component.score == 0
    assert "hallucination" not in component.description.lower()
