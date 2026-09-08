from __future__ import annotations

import ast
import datetime as dt
import re
import uuid
from pathlib import Path
from typing import Any

import yaml


ALLOWED_LEVELS = {"informational", "low", "medium", "high", "critical"}
ALLOWED_STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
ALLOWED_MODIFIERS = {"contains", "endswith", "startswith", "all"}
REQUIRED_FIELDS = {
    "title",
    "id",
    "status",
    "description",
    "author",
    "date",
    "tags",
    "logsource",
    "detection",
    "falsepositives",
    "level",
}
TECHNIQUE_TAG = re.compile(r"^attack\.t\d{4}(?:\.\d{3})?$")
DATE_TEXT = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def load_rule(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        rule = yaml.safe_load(handle)
    if not isinstance(rule, dict):
        raise ValueError(f"{path}: document must be a mapping")
    return rule


def _condition_names(condition: str) -> set[str]:
    tree = ast.parse(condition, mode="eval")
    return {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}


def _validate_condition_node(node: ast.AST) -> None:
    if isinstance(node, ast.Expression):
        _validate_condition_node(node.body)
        return
    if isinstance(node, ast.Name):
        return
    if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
        for value in node.values:
            _validate_condition_node(value)
        return
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        _validate_condition_node(node.operand)
        return
    raise ValueError(f"unsupported condition element: {ast.dump(node)}")


def validate_rule(rule: dict[str, Any], path: Path) -> list[str]:
    errors: list[str] = []
    missing = sorted(REQUIRED_FIELDS - set(rule))
    if missing:
        errors.append(f"missing fields: {', '.join(missing)}")

    try:
        rule_id = uuid.UUID(str(rule.get("id", "")))
        if rule_id.version != 4:
            errors.append("id must be a UUID version 4")
    except ValueError:
        errors.append("id must be a valid UUID")

    if rule.get("status") not in ALLOWED_STATUSES:
        errors.append(f"unsupported status: {rule.get('status')!r}")
    if rule.get("level") not in ALLOWED_LEVELS:
        errors.append(f"unsupported level: {rule.get('level')!r}")

    date_value = rule.get("date")
    if not isinstance(date_value, dt.date) and not DATE_TEXT.fullmatch(str(date_value)):
        errors.append("date must use YYYY-MM-DD")

    tags = rule.get("tags")
    if not isinstance(tags, list) or not any(TECHNIQUE_TAG.fullmatch(str(tag)) for tag in tags):
        errors.append("tags must contain at least one ATT&CK technique")

    false_positives = rule.get("falsepositives")
    if not isinstance(false_positives, list) or not false_positives:
        errors.append("falsepositives must be a non-empty list")

    logsource = rule.get("logsource")
    if not isinstance(logsource, dict):
        errors.append("logsource must be a mapping")
    elif logsource.get("category") != "process_creation" or logsource.get("product") != "windows":
        errors.append("logsource must be Windows process creation")

    detection = rule.get("detection")
    if not isinstance(detection, dict) or "condition" not in detection:
        errors.append("detection must contain a condition")
        return [f"{path}: {error}" for error in errors]

    selectors = {name: value for name, value in detection.items() if name != "condition"}
    for selector_name, selector in selectors.items():
        if not isinstance(selector, dict) or not selector:
            errors.append(f"{selector_name} must be a non-empty mapping")
            continue
        for field_expression in selector:
            parts = field_expression.split("|")
            unknown = set(parts[1:]) - ALLOWED_MODIFIERS
            if unknown:
                errors.append(
                    f"{selector_name}.{field_expression} uses unsupported modifiers: {sorted(unknown)}"
                )

    condition = detection.get("condition")
    if not isinstance(condition, str) or not condition.strip():
        errors.append("condition must be a non-empty string")
    else:
        try:
            tree = ast.parse(condition, mode="eval")
            _validate_condition_node(tree)
            unknown_names = _condition_names(condition) - set(selectors)
            if unknown_names:
                errors.append(f"condition references unknown selectors: {sorted(unknown_names)}")
        except (SyntaxError, ValueError) as exc:
            errors.append(f"invalid condition: {exc}")

    return [f"{path}: {error}" for error in errors]


def _compare(actual: Any, expected: Any, modifiers: list[str]) -> bool:
    actual_text = str(actual).casefold()
    expected_values = expected if isinstance(expected, list) else [expected]

    def compare_one(value: Any) -> bool:
        expected_text = str(value).casefold()
        if "contains" in modifiers:
            return expected_text in actual_text
        if "endswith" in modifiers:
            return actual_text.endswith(expected_text)
        if "startswith" in modifiers:
            return actual_text.startswith(expected_text)
        return actual_text == expected_text

    if "all" in modifiers:
        return all(compare_one(value) for value in expected_values)
    return any(compare_one(value) for value in expected_values)


def _matches_selector(selector: dict[str, Any], event: dict[str, Any]) -> bool:
    for field_expression, expected in selector.items():
        field_name, *modifiers = field_expression.split("|")
        if field_name not in event or not _compare(event[field_name], expected, modifiers):
            return False
    return True


def _evaluate_condition(node: ast.AST, selector_results: dict[str, bool]) -> bool:
    if isinstance(node, ast.Expression):
        return _evaluate_condition(node.body, selector_results)
    if isinstance(node, ast.Name):
        return selector_results[node.id]
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
        return all(_evaluate_condition(value, selector_results) for value in node.values)
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
        return any(_evaluate_condition(value, selector_results) for value in node.values)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not _evaluate_condition(node.operand, selector_results)
    raise ValueError(f"unsupported condition element: {ast.dump(node)}")


def matches_rule(rule: dict[str, Any], event: dict[str, Any]) -> bool:
    detection = rule["detection"]
    selectors = {name: value for name, value in detection.items() if name != "condition"}
    selector_results = {
        name: _matches_selector(selector, event) for name, selector in selectors.items()
    }
    tree = ast.parse(detection["condition"], mode="eval")
    _validate_condition_node(tree)
    return _evaluate_condition(tree, selector_results)
