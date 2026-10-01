from dataclasses import dataclass, field
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple
import yaml
from backend.app.models.entities import FindingSeverity, RuleResult

logger = logging.getLogger(__name__)


@dataclass
class RuleEvaluationResult:
    rule_id: str
    result: RuleResult
    control: str
    expected_value: Any
    actual_value: Any
    rationale: str
    remediation_guidance: str
    verification_method: str
    message: str
    collector_failed: bool = False
    failure_reason: Optional[str] = None


class RuleEngine:
    """
    Production YAML Security Rule Evaluation Engine.
    Implements all required comparison operators, boolean combinations,
    and strict UNKNOWN handling upon collector failures.
    """

    def evaluate_condition(
        self,
        condition: Dict[str, Any],
        observations_map: Dict[str, Any],
        failed_collectors: Set[str],
        control_collector_map: Dict[str, str]
    ) -> Tuple[RuleResult, Any, Any, str]:
        """
        Recursively evaluates conditions against normalized observations.
        Returns (result, actual_value, expected_value, evaluation_message).
        """
        # Handle Boolean operators: AND, OR, NOT
        if "AND" in condition:
            sub_results = []
            for sub_cond in condition["AND"]:
                res, actual, exp, msg = self.evaluate_condition(
                    sub_cond, observations_map, failed_collectors, control_collector_map
                )
                sub_results.append((res, actual, exp, msg))
                if res in (RuleResult.FAIL, RuleResult.UNKNOWN):
                    return res, actual, exp, f"Subcondition failed: {msg}"
            # If all passed
            return RuleResult.PASS, "all_matched", "all_matched", "All AND conditions satisfied"

        if "OR" in condition:
            sub_results = []
            for sub_cond in condition["OR"]:
                res, actual, exp, msg = self.evaluate_condition(
                    sub_cond, observations_map, failed_collectors, control_collector_map
                )
                if res == RuleResult.PASS:
                    return RuleResult.PASS, actual, exp, "At least one OR condition satisfied"
                sub_results.append((res, actual, exp, msg))
            # Return last sub result
            last_res = sub_results[-1] if sub_results else (RuleResult.FAIL, None, None, "No OR conditions passed")
            return last_res[0], last_res[1], last_res[2], "None of the OR conditions were satisfied"

        if "NOT" in condition:
            res, actual, exp, msg = self.evaluate_condition(
                condition["NOT"], observations_map, failed_collectors, control_collector_map
            )
            if res == RuleResult.UNKNOWN:
                return RuleResult.UNKNOWN, actual, exp, f"Cannot negate UNKNOWN: {msg}"
            inverted = RuleResult.FAIL if res == RuleResult.PASS else RuleResult.PASS
            return inverted, actual, exp, f"NOT condition evaluated (was {res.value})"

        operator = condition.get("operator", "equals").lower()
        actual_spec = condition.get("actual", {})
        expected = condition.get("expected")

        # Resolve actual value from observations
        if isinstance(actual_spec, dict) and "observation" in actual_spec:
            control_key = actual_spec["observation"]
        elif isinstance(actual_spec, str):
            control_key = actual_spec
        else:
            control_key = condition.get("control", "")

        # Check if the responsible collector failed (Requirement #20)
        responsible_collector = control_collector_map.get(control_key)
        if responsible_collector and responsible_collector in failed_collectors:
            return (
                RuleResult.UNKNOWN,
                None,
                expected,
                f"Collector '{responsible_collector}' failed to execute; control state cannot be determined"
            )

        if control_key not in observations_map:
            if operator == "not_exists":
                return RuleResult.PASS, None, None, f"Control '{control_key}' does not exist as expected"
            return (
                RuleResult.UNKNOWN,
                None,
                expected,
                f"Missing observation for control '{control_key}'"
            )

        actual = observations_map[control_key]

        # Evaluate comparison operator
        matched = False
        message = ""

        try:
            if operator == "equals":
                matched = (actual == expected)
                message = f"Actual '{actual}' equals expected '{expected}'" if matched else f"Actual '{actual}' does not equal expected '{expected}'"

            elif operator == "not_equals":
                matched = (actual != expected)
                message = f"Actual '{actual}' does not equal expected '{expected}'" if matched else f"Actual '{actual}' matches forbidden value '{expected}'"

            elif operator == "contains":
                if isinstance(actual, (list, tuple, set, str)):
                    matched = expected in actual
                else:
                    matched = False
                message = f"Target contains '{expected}'" if matched else f"Target does not contain expected '{expected}'"

            elif operator == "not_contains":
                if isinstance(actual, (list, tuple, set, str)):
                    matched = expected not in actual
                else:
                    matched = True
                message = f"Target does not contain '{expected}'" if matched else f"Target improperly contains '{expected}'"

            elif operator == "greater_than":
                matched = (float(actual) > float(expected))
                message = f"Value {actual} > {expected}" if matched else f"Value {actual} not greater than {expected}"

            elif operator == "less_than":
                matched = (float(actual) < float(expected))
                message = f"Value {actual} < {expected}" if matched else f"Value {actual} not less than {expected}"

            elif operator == "greater_than_or_equal":
                matched = (float(actual) >= float(expected))
                message = f"Value {actual} >= {expected}" if matched else f"Value {actual} < {expected}"

            elif operator == "less_than_or_equal":
                matched = (float(actual) <= float(expected))
                message = f"Value {actual} <= {expected}" if matched else f"Value {actual} > {expected}"

            elif operator == "in":
                if isinstance(expected, (list, tuple, set)):
                    matched = actual in expected
                else:
                    matched = False
                message = f"Actual '{actual}' is in expected set {expected}" if matched else f"Actual '{actual}' not in expected set {expected}"

            elif operator == "not_in":
                if isinstance(expected, (list, tuple, set)):
                    matched = actual not in expected
                else:
                    matched = True
                message = f"Actual '{actual}' is not in prohibited set {expected}" if matched else f"Actual '{actual}' is in prohibited set {expected}"

            elif operator == "regex":
                pattern = re.compile(str(expected))
                matched = bool(pattern.search(str(actual)))
                message = f"Actual '{actual}' matched regex '{expected}'" if matched else f"Actual '{actual}' did not match regex '{expected}'"

            elif operator == "exists":
                matched = (actual is not None and actual != "")
                message = f"Control '{control_key}' exists" if matched else f"Control '{control_key}' is missing or empty"

            elif operator == "not_exists":
                matched = (actual is None or actual == "")
                message = f"Control '{control_key}' does not exist" if matched else f"Control '{control_key}' exists when prohibited"

            else:
                return RuleResult.UNKNOWN, actual, expected, f"Unsupported operator '{operator}'"

            result = RuleResult.PASS if matched else RuleResult.FAIL
            return result, actual, expected, message

        except Exception as err:
            return RuleResult.UNKNOWN, actual, expected, f"Error evaluating condition: {str(err)}"

    def evaluate_rule(
        self,
        rule_dict: Dict[str, Any],
        observations_map: Dict[str, Any],
        failed_collectors: Set[str],
        control_collector_map: Dict[str, str],
        target_distro: Optional[str] = None
    ) -> RuleEvaluationResult:
        rule_id = rule_dict["id"]
        control = rule_dict.get("control", "")
        rationale = rule_dict.get("rationale", "")
        remediation = rule_dict.get("remediation_guidance", "")
        verification = rule_dict.get("verification_method", "")

        # Check supported distributions
        supported_distros = rule_dict.get("supported_distros", [])
        if supported_distros and target_distro and target_distro not in supported_distros and "all" not in supported_distros:
            return RuleEvaluationResult(
                rule_id=rule_id,
                result=RuleResult.NOT_APPLICABLE,
                control=control,
                expected_value=None,
                actual_value=target_distro,
                rationale=rationale,
                remediation_guidance=remediation,
                verification_method=verification,
                message=f"Rule only applies to distributions: {supported_distros}"
            )

        condition = rule_dict.get("condition", {})
        result, actual, expected, msg = self.evaluate_condition(
            condition, observations_map, failed_collectors, control_collector_map
        )

        return RuleEvaluationResult(
            rule_id=rule_id,
            result=result,
            control=control,
            expected_value=expected,
            actual_value=actual,
            rationale=rationale,
            remediation_guidance=remediation,
            verification_method=verification,
            message=msg,
            collector_failed=(result == RuleResult.UNKNOWN and "Collector" in msg)
        )
