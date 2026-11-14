import json
from pathlib import Path

import pytest

from colossus.contracts.core import DomainError
from colossus.verify.campaign import assess_campaign

ROOT = Path(__file__).parents[2]
CANDIDATES = json.loads((ROOT / "evaluation" / "repository-candidates.json").read_text())


def test_repository_candidate_roster_is_rejected():
    with pytest.raises(DomainError, match="Candidate-only roster") as caught:
        assess_campaign(CANDIDATES)
    assert caught.value.code == "candidate_only"
    assert CANDIDATES["scored_execution_allowed"] is False


def test_frozen_lock_stays_unrun_even_when_preflight_is_complete():
    manifest = {
        "status": "frozen",
        "scored_execution_allowed": False,
        "repositories": [
            {
                "repo_id": "U03",
                "source_commit": "a" * 40,
                "source_archive_sha256": "b" * 64,
                "oracle_id": "dsvw-functional-security-v1",
            },
            {"repo_id": "U01"},
        ],
    }
    report = assess_campaign(manifest)
    assert report["executed"] is False
    assert report["scores"] is None
    assert report["cases"][0]["outcome"] == "unrun"
    assert report["cases"][0]["missing"] == []
    assert report["cases"][1]["reason"] == "preflight incomplete"


def test_scored_execution_flag_cannot_start_a_run():
    with pytest.raises(DomainError, match="does not start scored") as caught:
        assess_campaign(
            {
                "status": "frozen",
                "scored_execution_allowed": True,
                "repositories": [{"repo_id": "U03"}],
            }
        )
    assert caught.value.code == "campaign_not_executed"
