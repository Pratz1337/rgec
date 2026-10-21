"""Paper model ids map to real Hugging Face weights. No GPU call."""

from modal_llm import HF_IDS
from unauthorized_channels.tasks import MODELS


def test_both_paper_models_have_hf_weights() -> None:
    assert MODELS[0] in HF_IDS
    assert MODELS[1] in HF_IDS
    assert HF_IDS[MODELS[0]] == "Qwen/Qwen3-Coder-30B-A3B-Instruct"
    assert "Devstral-Small-2" in HF_IDS[MODELS[1]]


def test_modal_flag_is_host_side_only() -> None:
    from unauthorized_channels.prompts import SOLO_SYSTEM_PROMPT

    assert "modal" not in SOLO_SYSTEM_PROMPT.lower()
    assert "huggingface" not in SOLO_SYSTEM_PROMPT.lower()
