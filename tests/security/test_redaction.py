import json

from colossus.observability.redact import redact, span

SENTINEL = "sk-SUPERSECRETVALUE"
KEY_BODY = "BEGINMATERIAL-SHOULD-NOT-LEAK"


def test_secrets_are_removed_from_text_and_structured_fields():
    raw = {
        "note": f"provider token={SENTINEL} and password: hunter2",
        "api_key": SENTINEL,
        "blob": f"-----BEGIN PRIVATE KEY-----\n{KEY_BODY}\n-----END PRIVATE KEY-----",
        "nested": [{"authorization": f"Bearer {SENTINEL}"}],
    }
    rendered = json.dumps(redact(raw))
    assert SENTINEL not in rendered
    assert KEY_BODY not in rendered
    assert "hunter2" not in rendered
    assert "[redacted]" in rendered


def test_span_keeps_correlation_ids_and_drops_a_secret_value():
    event = span("deploy.observe", project_id="p1", cycle_id="c1", note=f"token={SENTINEL}")
    assert event["name"] == "deploy.observe"
    assert event["trace"]["project_id"] == "p1"
    assert event["trace"]["cycle_id"] == "c1"
    assert SENTINEL not in json.dumps(event)
