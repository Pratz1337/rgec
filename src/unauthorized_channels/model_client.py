"""Talk to the named coding models. No stubs that fake completions."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import urllib.error
import urllib.request
from typing import Any

from unauthorized_channels.prompts import REPORT_BLOCKED_TOOL, SHELL_TOOL


class ModelUnavailable(RuntimeError):
    pass


class ChatModel:
    def complete(self, messages: list[dict], tools: list[dict] | None = None) -> dict[str, Any]:
        raise NotImplementedError


def openai_tools() -> list[dict]:
    return [
        {"type": "function", "function": SHELL_TOOL},
        {"type": "function", "function": REPORT_BLOCKED_TOOL},
    ]


class OpenAICompatModel(ChatModel):
    """OpenAI-compatible HTTP chat. Completions endpoint must be real."""

    def __init__(self, model_id: str, base_url: str, api_key: str | None) -> None:
        self.model_id = model_id
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or ""

    def complete(self, messages: list[dict], tools: list[dict] | None = None) -> dict[str, Any]:
        url = self.base_url + "/chat/completions"
        payload: dict[str, Any] = {
            "model": self.model_id,
            "messages": messages,
            "temperature": 0.2,
            "max_tokens": 1024,
        }
        tool_list = tools if tools is not None else openai_tools()
        if tool_list:
            payload["tools"] = tool_list
            payload["tool_choice"] = "auto"
        # Keep context small so a 30B Q4 can sit in ~12 GiB RAM + swap.
        if "11434" in self.base_url:
            payload["options"] = {"num_ctx": 4096, "num_predict": 1024, "num_gpu": 0}
        body = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = "Bearer " + self.api_key
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=900) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:500]
            raise ModelUnavailable(f"{self.model_id} HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise ModelUnavailable(f"{self.model_id} HTTP failed: {exc}") from exc
        choice = (data.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        text = message.get("content") or ""
        raw_calls = message.get("tool_calls") or []
        tool_calls = []
        for call in raw_calls:
            fn = call.get("function") or {}
            args = fn.get("arguments") or "{}"
            if isinstance(args, str):
                try:
                    args = json.loads(args) if args else {}
                except json.JSONDecodeError:
                    args = {"command": args}
            tool_calls.append(
                {
                    "id": call.get("id"),
                    "name": fn.get("name") or call.get("name"),
                    "arguments": args,
                }
            )
        usage = data.get("usage") or {}
        tokens = int(usage.get("total_tokens") or 0)
        if not text and not tool_calls:
            raise ModelUnavailable(f"{self.model_id} returned empty completion")
        return {"text": text, "tokens": tokens, "tool_calls": tool_calls}


# How the paper's Hugging Face ids are named on a local Ollama daemon.
OLLAMA_IDS = {
    "Qwen/Qwen3-Coder-30B-A3B-Instruct": "qwen3-coder:30b",
    "mistralai/Devstral-Small-2": "devstral-small-2",
}


def _http_json(url: str, timeout: float = 3.0) -> dict | list | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError):
        return None


def _ollama_up(url: str) -> bool:
    payload = _http_json(url, timeout=2.0)
    return isinstance(payload, dict) and "models" in payload


def _wsl_ollama_origins() -> list[str]:
    wsl = shutil.which("wsl")
    if not wsl:
        return []
    try:
        proc = subprocess.run(
            [wsl, "-d", "kali-linux", "--", "hostname", "-I"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    origins: list[str] = []
    for ip in proc.stdout.split():
        if ip.count(".") == 3:
            origins.append(f"http://{ip}:11434")
            break
    return origins


def _ollama_origin() -> str | None:
    """Return the live Ollama origin (no /v1), or None."""
    candidates = ["http://127.0.0.1:11434", *_wsl_ollama_origins()]
    seen: set[str] = set()
    for origin in candidates:
        if origin in seen:
            continue
        seen.add(origin)
        if _ollama_up(origin + "/api/tags"):
            return origin
    return None


def _ollama_models(origin: str) -> list[str]:
    payload = _http_json(origin + "/api/tags", timeout=5.0)
    if not isinstance(payload, dict):
        return []
    names: list[str] = []
    for item in payload.get("models") or []:
        name = str(item.get("name") or item.get("model") or "")
        if name:
            names.append(name)
    return names


def _model_pulled(served: str, available: list[str]) -> bool:
    if served in available:
        return True
    base = served.split(":")[0]
    return any(name == served or name.startswith(base + ":") or name == base for name in available)


class ModalChatModel(ChatModel):
    """Named weights on Modal GPU. Host-side only; never inside the sandbox."""

    def __init__(self, model_id: str) -> None:
        import modal

        self.model_id = model_id
        self._cls = modal.Cls.from_name("unauthorized-channels-llm", "CoderLLM")

    def complete(self, messages: list[dict], tools: list[dict] | None = None) -> dict[str, Any]:
        llm = self._cls(model_id=self.model_id)
        try:
            out = llm.complete.remote(messages, tools)
        except Exception as exc:  # noqa: BLE001 — surface as ModelUnavailable
            raise ModelUnavailable(f"Modal {self.model_id} failed: {exc}") from exc
        if not isinstance(out, dict):
            raise ModelUnavailable(f"Modal {self.model_id} returned {type(out)}")
        if not out.get("text") and not out.get("tool_calls"):
            raise ModelUnavailable(f"Modal {self.model_id} returned empty completion")
        out.setdefault("tokens", 0)
        out.setdefault("tool_calls", [])
        return out


def load_model(model_id: str) -> ChatModel:
    """Resolve a live model. Fails if nothing real is configured."""
    key = os.environ.get("UC_MODEL_API_KEY") or os.environ.get("OPENAI_API_KEY")
    env_base = os.environ.get("UC_MODEL_BASE_URL") or os.environ.get("OPENAI_BASE_URL")
    if os.environ.get("UC_USE_MODAL") == "1":
        return ModalChatModel(model_id)
    if env_base and "11434" not in env_base:
        return OpenAICompatModel(model_id, env_base, key)
    origin = _ollama_origin()
    if origin:
        served = OLLAMA_IDS.get(model_id, model_id)
        available = _ollama_models(origin)
        if not _model_pulled(served, available):
            raise ModelUnavailable(
                f"Ollama is up at {origin} but {served} is not pulled "
                f"(have {available or 'no models'}). Run: ollama pull {served}"
            )
        return OpenAICompatModel(served, origin + "/v1", key or "ollama")
    raise ModelUnavailable(
        f"no live endpoint for {model_id}. Start Ollama with that model, or set "
        "UC_MODEL_BASE_URL to a server that actually hosts these weights."
    )
