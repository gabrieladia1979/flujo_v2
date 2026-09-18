import json
import logging
import os
import time
from threading import BoundedSemaphore, Lock
from typing import Any

from services.slm_explanation import (
    SLMExplanationContext,
    build_slm_prompt_messages,
    render_server_fallback,
)

logger = logging.getLogger(__name__)

DEFAULT_MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "model",
    "qwen2.5-3b-instruct-q4_k_m.gguf",
)
MODEL_PATH = os.getenv("SLM_MODEL_LOCAL_PATH", DEFAULT_MODEL_PATH)

_slm_instance = None
_slm_initialization_lock = Lock()
# A single llama.cpp instance is not a safe target for parallel generation. Keep
# this process-level bound at one; run more ECS tasks to scale throughput.
_slm_inference_lock = BoundedSemaphore(value=1)


def get_slm_instance():
    """Initialize and cache the local model once per application process."""
    global _slm_instance
    if _slm_instance is not None:
        return _slm_instance

    with _slm_initialization_lock:
        if _slm_instance is not None:
            return _slm_instance
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(f"SLM GGUF model was not found at {MODEL_PATH}")

        try:
            from llama_cpp import Llama

            _slm_instance = Llama(
                model_path=MODEL_PATH,
                n_ctx=int(os.getenv("SLM_CONTEXT_TOKENS", "2048")),
                n_gpu_layers=0,
                n_threads=int(os.getenv("SLM_THREADS", "4")),
                verbose=False,
            )
        except ImportError as error:
            raise ImportError("llama-cpp-python is required for SLM inference") from error
    return _slm_instance


def is_slm_loaded() -> bool:
    return _slm_instance is not None


def slm_runtime_status() -> dict[str, Any]:
    """Expose readiness facts without loading the model as a health-check side effect."""
    return {
        "model_path": MODEL_PATH,
        "model_file_exists": os.path.exists(MODEL_PATH),
        "loaded": is_slm_loaded(),
        "max_concurrent_generations": 1,
    }


def generate_slm_explanation(context: SLMExplanationContext) -> str:
    """Generate one explanation, falling back immediately while the SLM is busy."""
    start_time = time.time()
    if not _slm_inference_lock.acquire(blocking=False):
        logger.warning("SLM is busy; returning deterministic fallback without queuing inference.")
        return render_server_fallback(context)

    try:
        messages = build_slm_prompt_messages(context)
        llm = get_slm_instance()

        response = llm.create_chat_completion(
            messages=messages,
            temperature=0.1,
            max_tokens=300,
            response_format={"type": "json_object"},
        )
        raw_output = response["choices"][0]["message"]["content"].strip()

        try:
            json.loads(raw_output)
            return raw_output
        except json.JSONDecodeError:
            logger.warning("SLM returned invalid JSON; retrying once.")
            messages.append({"role": "assistant", "content": raw_output})
            messages.append(
                {
                    "role": "user",
                    "content": "Return only valid JSON that follows the requested schema.",
                }
            )
            retry_response = llm.create_chat_completion(
                messages=messages,
                temperature=0.1,
                max_tokens=300,
                response_format={"type": "json_object"},
            )
            retry_output = retry_response["choices"][0]["message"]["content"].strip()
            json.loads(retry_output)
            logger.info("SLM retry completed in %.2fs", time.time() - start_time)
            return retry_output
    except Exception as error:
        logger.error(
            "SLM failed; using deterministic fallback after %.2fs: %s",
            time.time() - start_time,
            error,
        )
        return render_server_fallback(context)
    finally:
        _slm_inference_lock.release()
