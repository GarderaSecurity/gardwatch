from typing import Optional, Dict, Any
from .models import Dependency, CheckContext, TrustReport, DepsDevPackage, DepsDevVersionDetails, OpenSSFScorecard, DepsDevProject, ScoreComponent
from .checks import create_default_registry

class TrustEngine:
    def __init__(self):
        self.registry = create_default_registry()

    def evaluate(
        self,
        dependency: Dependency,
        package_info: Optional[Dict[str, Any]],
        version_details: Optional[Dict[str, Any]],
        scorecard: Optional[Dict[str, Any]],
        download_count: Optional[int] = None,
        project_data: Optional[Dict[str, Any]] = None,
        dependent_count: Optional[int] = None
    ) -> TrustReport:
        
        # Parse into Pydantic models (soft validation)
        # We assume the dicts match roughly; if not, pydantic might raise validation errors.
        # Ideally clients return models, but we do it here for now to bridge the gap.
        
        pkg_model = DepsDevPackage(**package_info) if package_info else None
        ver_model = DepsDevVersionDetails(**version_details) if version_details else None
        
        sc_model = None
        if scorecard:
            # Scorecard structure from deps.dev might be nested or direct
            # Based on earlier curl: {"overallScore": 5.7, ...}
            sc_model = OpenSSFScorecard(**scorecard)
            
        proj_model = DepsDevProject(**project_data) if project_data else None

        context = CheckContext(
            dependency=dependency,
            package_info=pkg_model,
            version_details=ver_model,
            scorecard=sc_model,
            download_count=download_count,
            project_data=proj_model,
            dependent_count=dependent_count
        )

        # Baseline
        if not context.version_details:
             comp = ScoreComponent(
                 label="Registry Check",
                 score=-100,
                 description="Package not found in deps.dev (Possible hallucination or very new)",
                 category="Trust"
             )
             return TrustReport(
                status="CRITICAL",
                score=0,
                components=[comp],
                reason=comp.description,
                details=[]
            )

        # Run Checks
        components = self.registry.run_all(context)

        # Calculate Score
        current_score = 100
        critical_failure = False
        malware_found = False
        
        for comp in components:
            if comp.label == "Malware Database" and comp.score < 0:
                malware_found = True
            current_score += comp.score
            
        final_score = max(0, min(100, current_score))
        
        # Determine Status
        status = "SAFE"
        if malware_found:
            status = "CRITICAL"
            final_score = 0
        elif final_score < 50:
            status = "CRITICAL"
        elif final_score < 80:
            status = "SUSPICIOUS"
            
        # Helper to find primary reason
        reason = "All checks passed"
        # Prioritize negative reasons
        negatives = [c for c in components if c.score < 0]
        if negatives:
            # Sort by severity
            negatives.sort(key=lambda x: x.score)
            reason = negatives[0].description
        elif components:
            # Or just show "Verified" if all good
            positives = [c for c in components if c.score > 0]
            if positives:
                reason = "Verified Safe"

        # Special Override: Logic for "Established" packages avoiding "Young" penalty is tricky 
        # with independent checks if they don't share state.
        # However, our `check_age` now returns +20/10/0/-20.
        # If it returns +20, it adds to the score. If -20, it subtracts.
        # This additive model works without explicit "override" flags.
        
        return TrustReport(
            status=status,
            score=final_score,
            components=components,
            reason=reason,
            details=[c.description for c in components if c.score < 0]
        )