"""Modal GPU inference for the two named coding models.

Host-side only. Agent sandboxes never receive Modal/HF credentials.
Weights are the paper's Hugging Face ids (Devstral Small 2 maps to
the official 24B Instruct checkpoint).
"""

import modal

APP_NAME = "unauthorized-channels-llm"
MINUTES = 60

# Paper-facing id -> weights actually loaded.
HF_IDS = {
    "Qwen/Qwen3-Coder-30B-A3B-Instruct": "Qwen/Qwen3-Coder-30B-A3B-Instruct",
    "mistralai/Devstral-Small-2": "mistralai/Devstral-Small-2-24B-Instruct-2512",
}

vllm_image = (
    modal.Image.from_registry("nvidia/cuda:12.9.0-devel-ubuntu22.04", add_python="3.12")
    .entrypoint([])
    .uv_pip_install(
        "vllm==0.21.0",
        "huggingface-hub==0.36.0",
        "hf_transfer",
        "mistral_common",
    )
    .env({"HF_XET_HIGH_PERFORMANCE": "1"})
)

hf_cache_vol = modal.Volume.from_name("uc-huggingface-cache", create_if_missing=True)
vllm_cache_vol = modal.Volume.from_name("uc-vllm-cache", create_if_missing=True)

app = modal.App(APP_NAME)


@app.cls(
    image=vllm_image,
    gpu="A100-80GB",
    timeout=20 * MINUTES,
    scaledown_window=2 * MINUTES,
    secrets=[modal.Secret.from_name("huggingface-secret")],
    volumes={
        "/root/.cache/huggingface": hf_cache_vol,
        "/root/.cache/vllm": vllm_cache_vol,
    },
)
class CoderLLM:
    model_id: str = modal.parameter()

    @modal.enter()
    def load(self) -> None:
        from vllm import LLM

        hf_id = HF_IDS.get(self.model_id, self.model_id)
        kwargs = {
            "model": hf_id,
            "trust_remote_code": True,
            "max_model_len": 32768,
            "gpu_memory_utilization": 0.90,
            "dtype": "auto",
        }
        if "Devstral" in hf_id or "devstral" in hf_id.lower():
            kwargs["tokenizer_mode"] = "mistral"
            kwargs["config_format"] = "mistral"
            kwargs["load_format"] = "mistral"
        self.hf_id = hf_id
        self.llm = LLM(**kwargs)

    @modal.method()
    def complete(self, messages: list, tools: list | None = None) -> dict:
        from vllm import SamplingParams

        sp = SamplingParams(temperature=0.2, max_tokens=1024)
        chat_kwargs: dict = {"sampling_params": sp, "use_tqdm": False}
        if tools:
            chat_kwargs["tools"] = tools
        try:
            outs = self.llm.chat(messages, **chat_kwargs)
        except TypeError:
            chat_kwargs.pop("tools", None)
            chat_kwargs.pop("use_tqdm", None)
            outs = self.llm.chat(messages, **chat_kwargs)
        except Exception as exc:
            raise RuntimeError(f"{self.hf_id} complete failed: {exc}") from None
        out = outs[0]
        text = ""
        tokens = 0
        tool_calls: list[dict] = []
        if hasattr(out, "outputs") and out.outputs:
            text = out.outputs[0].text or ""
            tokens = len(getattr(out.outputs[0], "token_ids", []) or [])
        elif hasattr(out, "choices"):
            msg = out.choices[0].message
            text = getattr(msg, "content", None) or ""
            raw = getattr(msg, "tool_calls", None) or []
            for call in raw:
                fn = getattr(call, "function", None)
                if fn is None:
                    continue
                args = getattr(fn, "arguments", "{}")
                tool_calls.append({"name": getattr(fn, "name", ""), "arguments": args})
        if not text and not tool_calls:
            raise RuntimeError(f"{self.hf_id} returned empty completion")
        return {"text": text, "tokens": tokens, "tool_calls": tool_calls}


@app.local_entrypoint()
def main(model: str = "Qwen/Qwen3-Coder-30B-A3B-Instruct"):
    """Real ping: the named weights must produce a completion on GPU."""
    llm = CoderLLM(model_id=model)
    out = llm.complete.remote(
        [{"role": "user", "content": "Reply with the single word pong and nothing else."}]
    )
    print(out)
    if "pong" not in (out.get("text") or "").lower():
        raise SystemExit(f"unexpected completion: {out!r}")
