"""LLM configuration.

Ollama by default so the whole POC runs locally with no API key and no bill.
Set `LLM_PROVIDER=openai` (plus `OPENAI_API_KEY`) to swap backends -- nothing else
in the project knows or cares which one is in use.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

try:  # optional convenience, not a hard dependency
    from dotenv import dotenv_values, load_dotenv

    # Standard precedence: a variable already exported in the shell beats .env,
    # so `LLM_MODEL=x python main.py` still works for a one-off.
    load_dotenv()

    def _warn_on_shadowed_secrets() -> list[str]:
        """Say so when .env holds a different value than the shell is using.

        This is worth a warning rather than silence: .env is the documented
        place to put keys, so a stale exported variable shadowing it looks
        exactly like "my new credentials are being rejected". It cost a
        debugging cycle once already -- a live Tenable pull kept returning 401
        against a key the user had already replaced in .env.
        """
        import os as _os

        shadowed: list[str] = []
        for name, file_value in (dotenv_values() or {}).items():
            if not file_value:
                continue
            live_value = _os.environ.get(name)
            if live_value is not None and live_value != file_value:
                shadowed.append(name)
        return shadowed

    SHADOWED_BY_SHELL = _warn_on_shadowed_secrets()
except ImportError:  # pragma: no cover
    SHADOWED_BY_SHELL = []

DEFAULT_OLLAMA_MODEL = "llama3.1:8b"
DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"


@dataclass
class LLMSettings:
    provider: str = os.getenv("LLM_PROVIDER", "ollama").strip().lower()
    model: str | None = os.getenv("LLM_MODEL") or None
    base_url: str | None = os.getenv("OLLAMA_BASE_URL") or None
    temperature: float = float(os.getenv("LLM_TEMPERATURE", "0.2"))
    # Agents are analysts, not chatterboxes. Enough headroom for a 400-word section
    # plus tool-call overhead; small models truncate mid-sentence below ~2000.
    max_tokens: int = int(os.getenv("LLM_MAX_TOKENS", "2400"))

    def resolved_model(self) -> str:
        if self.model:
            return self.model
        return DEFAULT_OLLAMA_MODEL if self.provider == "ollama" else DEFAULT_OPENAI_MODEL

    def describe(self) -> str:
        return f"{self.provider}:{self.resolved_model()}"


def build_llm(settings: LLMSettings | None = None):
    """Return a configured `crewai.LLM`. Imported lazily so `--offline` needs no CrewAI."""
    from crewai import LLM

    settings = settings or LLMSettings()
    model = settings.resolved_model()
    provider = settings.provider

    if provider == "ollama":
        base_url = settings.base_url or DEFAULT_OLLAMA_BASE_URL
        return LLM(
            model=model if model.startswith("ollama/") else f"ollama/{model}",
            base_url=base_url,
            temperature=settings.temperature,
            max_tokens=settings.max_tokens,
        )

    if provider == "openai":
        if not os.getenv("OPENAI_API_KEY"):
            raise RuntimeError(
                "LLM_PROVIDER=openai but OPENAI_API_KEY is not set. "
                "Set the key, or use the default local provider (LLM_PROVIDER=ollama)."
            )
        return LLM(
            model=model,
            temperature=settings.temperature,
            max_tokens=settings.max_tokens,
        )

    # Anything else is passed through to LiteLLM as-is (azure/…, anthropic/…, groq/…).
    return LLM(model=model, temperature=settings.temperature, max_tokens=settings.max_tokens)


def preflight(settings: LLMSettings | None = None) -> tuple[bool, str]:
    """Cheap reachability check so a missing Ollama fails with advice, not a stack trace."""
    settings = settings or LLMSettings()
    if settings.provider != "ollama":
        if settings.provider == "openai" and not os.getenv("OPENAI_API_KEY"):
            return False, "OPENAI_API_KEY is not set."
        return True, "ok"

    import json
    import urllib.error
    import urllib.request

    base_url = (settings.base_url or DEFAULT_OLLAMA_BASE_URL).rstrip("/")
    try:
        with urllib.request.urlopen(f"{base_url}/api/tags", timeout=4) as response:
            tags = json.loads(response.read())
    except (urllib.error.URLError, OSError, TimeoutError):
        return False, (
            f"Ollama is not reachable at {base_url}.\n"
            f"  Start it with:  ollama serve\n"
            f"  Pull a model:   ollama pull {settings.resolved_model()}\n"
            f"  Or run without an LLM:  python main.py --offline"
        )

    installed = [m.get("name", "") for m in tags.get("models", [])]
    wanted = settings.resolved_model().removeprefix("ollama/")
    if installed and not any(name == wanted or name.startswith(f"{wanted.split(':')[0]}:") for name in installed):
        return False, (
            f"Ollama is running but '{wanted}' is not installed.\n"
            f"  Installed: {', '.join(installed) or 'none'}\n"
            f"  Pull it:   ollama pull {wanted}\n"
            f"  Or point at an installed one:  LLM_MODEL=<name> python main.py"
        )
    return True, "ok"
