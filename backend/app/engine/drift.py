from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from backend.app.schemas.schemas import DriftComparisonResponse, DriftItem


class DriftDetector:
    """
    Compares baseline and target assessment observations to isolate configuration drift.
    Adheres to requirement #33: Detects changes objectively without labeling as malicious.
    """

    def compare(
        self,
        host_id: str,
        host_name: str,
        baseline_assessment_id: str,
        target_assessment_id: str,
        baseline_date: datetime,
        target_date: datetime,
        baseline_observations: List[Dict[str, Any]],
        target_observations: List[Dict[str, Any]],
        rule_severities: Optional[Dict[str, str]] = None
    ) -> DriftComparisonResponse:
        rule_severities = rule_severities or {}

        # Map by control key
        baseline_map: Dict[str, Dict[str, Any]] = {
            obs["control"]: obs for obs in baseline_observations
        }
        target_map: Dict[str, Dict[str, Any]] = {
            obs["control"]: obs for obs in target_observations
        }

        all_controls = set(baseline_map.keys()).union(set(target_map.keys()))
        drift_items: List[DriftItem] = []

        for control in sorted(all_controls):
            base_obs = baseline_map.get(control)
            tgt_obs = target_map.get(control)

            base_val = base_obs["value"] if base_obs else None
            tgt_val = tgt_obs["value"] if tgt_obs else None

            # Detect difference
            if base_val != tgt_val:
                category = tgt_obs["category"] if tgt_obs else (base_obs["category"] if base_obs else "general")
                first_obs = base_obs["collected_at"] if base_obs else baseline_date
                last_obs = tgt_obs["collected_at"] if tgt_obs else target_date

                # Human-readable change description
                if base_val is None:
                    desc = f"New control observation recorded: '{tgt_val}'"
                elif tgt_val is None:
                    desc = f"Previous observation for '{control}' is no longer reported"
                else:
                    desc = f"Observed modification from '{base_val}' to '{tgt_val}'"

                severity = rule_severities.get(control, "INFO")

                drift_items.append(DriftItem(
                    control=control,
                    category=category,
                    previous_value=base_val,
                    current_value=tgt_val,
                    first_observed=first_obs if isinstance(first_obs, datetime) else baseline_date,
                    last_observed=last_obs if isinstance(last_obs, datetime) else target_date,
                    severity=severity,
                    description=desc
                ))

        return DriftComparisonResponse(
            host_id=host_id,
            host_name=host_name,
            baseline_assessment_id=baseline_assessment_id,
            target_assessment_id=target_assessment_id,
            baseline_date=baseline_date,
            target_date=target_date,
            total_changes=len(drift_items),
            changes=drift_items
        )


drift_detector = DriftDetector()
