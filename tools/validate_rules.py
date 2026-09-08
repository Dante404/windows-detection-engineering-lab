from __future__ import annotations

import sys
from pathlib import Path

from rule_validation import load_rule, validate_rule


ROOT = Path(__file__).resolve().parents[1]
RULE_DIR = ROOT / "rules" / "sigma"


def main() -> int:
    paths = sorted(RULE_DIR.glob("*.yml"))
    if not paths:
        print(f"No Sigma rules found in {RULE_DIR}", file=sys.stderr)
        return 1

    errors: list[str] = []
    identifiers: dict[str, Path] = {}
    titles: dict[str, Path] = {}

    for path in paths:
        rule = load_rule(path)
        errors.extend(validate_rule(rule, path.relative_to(ROOT)))

        identifier = str(rule.get("id"))
        title = str(rule.get("title"))
        if identifier in identifiers:
            errors.append(f"{path.relative_to(ROOT)}: duplicate id also used by {identifiers[identifier]}")
        else:
            identifiers[identifier] = path.relative_to(ROOT)
        if title in titles:
            errors.append(f"{path.relative_to(ROOT)}: duplicate title also used by {titles[title]}")
        else:
            titles[title] = path.relative_to(ROOT)

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print(f"Validated {len(paths)} Sigma rules.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
