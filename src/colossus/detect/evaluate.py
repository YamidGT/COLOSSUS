"""Score stored findings against frozen evaluator input; never start targets or inference."""

import argparse
import json
import re
from pathlib import Path

from colossus.contracts.models import Finding


def score(findings: list[Finding], truth: dict, source_commit: str) -> dict:
    if (
        not re.fullmatch(r"[a-f0-9]{40}", source_commit)
        or truth.get("source_commit") != source_commit
    ):
        raise ValueError("Findings and evaluator truth must bind the same frozen commit")
    cases = truth.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("Evaluator truth must contain nonempty reviewed cases")
    ids = set()
    for item in cases:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("id"), str)
            or not isinstance(item.get("file"), str)
            or type(item.get("line")) is not int
            or item["line"] < 1
            or not isinstance(item.get("cwe"), str)
            or not re.fullmatch(r"CWE-[1-9][0-9]*", item["cwe"])
            or type(item.get("window", 0)) is not int
            or not 0 <= item.get("window", 0) <= 10
            or item["id"] in ids
        ):
            raise ValueError("Malformed or duplicate evaluator case")
        ids.add(item["id"])
    # The same underlying finding appearing twice is not two successes.
    unique = {}
    for finding in findings:
        previous = unique.get(finding.fingerprint)
        if previous is None or (
            finding.disposition != "suppress"
            and (
                previous.disposition == "suppress"
                or (previous.status != "confirmed" and finding.status == "confirmed")
            )
        ):
            unique[finding.fingerprint] = finding
    reported = [f for f in unique.values() if f.disposition != "suppress"]

    def matches(item, finding):
        location = finding.location or {}
        line = location.get("line")
        return (
            type(line) is int
            and location.get("file") == item["file"]
            and finding.cwe == item["cwe"]
            and abs(line - item["line"]) <= item.get("window", 0)
        )

    found = [item["id"] for item in cases if any(matches(item, f) for f in reported)]
    confirmed = [
        item["id"]
        for item in cases
        if any(matches(item, f) and f.status == "confirmed" for f in reported)
    ]
    matched = [f for f in reported if any(matches(item, f) for item in cases)]
    return {
        "source_commit": source_commit,
        "matching": "same file + CWE + declared line window",
        "reference_total": len(cases),
        "reference_recall": len(found) / len(cases),
        "found": found,
        "missed": [item["id"] for item in cases if item["id"] not in found],
        "confirmed_dynamic": confirmed,
        "reported_unique": len(reported),
        "matched_reported": len(matched),
        "reference_match_rate": len(matched) / len(reported) if reported else None,
        "unadjudicated_reported": len(reported) - len(matched),
        "suppressed_unique": len(unique) - len(reported),
        "duplicate_records": len(findings) - len(unique),
        "precision": None,
        "precision_note": "Unmatched findings require adjudication; location matching does not establish precision",
        "execution": "stored_results_only; no target or model executed",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    args = parser.parse_args()
    findings = json.loads(args.findings.read_text())
    truth = json.loads(args.truth.read_text())
    print(
        json.dumps(
            score(
                [Finding.model_validate(f) for f in findings["findings"]],
                truth,
                findings["source_commit"],
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
