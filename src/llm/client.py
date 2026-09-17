"""One-shot Composer 2.5 client. No tools, no follow-up, no repo walk."""

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Callable, Optional

JSON_ONLY = "JSON only"
MODEL = "composer-2.5"
JSON_OBJECT = (
    "Reply MUST be a single JSON object matching the requested schema. "
    "No markdown, no commentary."
)
_REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_dotenv(path: Path) -> None:
    """Set unset keys from a KEY=VALUE file. Does not overwrite the environment."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        if not key or key in os.environ:
            continue
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        os.environ[key] = val


_load_dotenv(_REPO_ROOT / ".env")


def available() -> bool:
    return bool(os.environ.get("CURSOR_API_KEY"))


def should_run(no_llm: bool = False) -> bool:
    """False when --no-llm or CURSOR_API_KEY is missing. Overlay-only path."""
    return (not no_llm) and available()


def complete(prompt: str) -> str:
    key = os.environ.get("CURSOR_API_KEY")
    if not key:
        raise RuntimeError("CURSOR_API_KEY missing")
    try:
        from cursor_sdk import Agent, AgentOptions, LocalAgentOptions
    except ImportError as e:
        raise RuntimeError("cursor-sdk not installed") from e
    scratch = tempfile.mkdtemp(prefix="wemu-llm-")
    try:
        result = Agent.prompt(
            prompt,
            AgentOptions(
                api_key=key,
                model=MODEL,
                tools=[],
                local=LocalAgentOptions(cwd=scratch),
            ),
        )
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    if getattr(result, "status", "finished") == "error":
        raise RuntimeError("llm run failed")
    text = getattr(result, "result", None)
    return text if isinstance(text, str) else ""


def parse_json(text: str) -> Any:
    """First JSON object in `text`. Raises ValueError if none / invalid."""
    start = text.find("{")
    if start < 0:
        raise ValueError("no JSON object")
    try:
        obj, _ = json.JSONDecoder().raw_decode(text[start:])
    except json.JSONDecodeError as e:
        raise ValueError("invalid JSON") from e
    if not isinstance(obj, dict):
        raise ValueError("JSON root must be an object")
    return obj


def ask_json(prompt: str, complete_fn: Optional[Callable[[str], str]] = None) -> Any:
    fn = complete_fn or complete
    instructed = JSON_OBJECT + "\n\n" + prompt
    try:
        return parse_json(fn(instructed))
    except ValueError:
        try:
            return parse_json(fn(instructed.rstrip() + "\n" + JSON_ONLY))
        except ValueError as e:
            raise ValueError("LLM response is not parseable JSON after retry") from e
