from pathlib import Path


def test_action_center_does_not_embed_secrets_or_html():
    root = Path("frontend")
    text = "\n".join(
        path.read_text()
        for path in root.rglob("*")
        if path.suffix in {".ts", ".tsx", ".css", ".html", ".json"} and "node_modules" not in path.parts
    )
    assert "dangerouslySetInnerHTML" not in text
    assert "localStorage" not in text
    assert "VITE_" not in text
    assert "PRIVATE KEY" not in text
    assert "MISTRAL" not in text
