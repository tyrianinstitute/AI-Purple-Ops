"""Connection helpers for adapter testing and validation."""

from __future__ import annotations

import os
from pathlib import Path

import requests


def get_env_or_prompt(env_var: str, prompt: str, default: str | None = None) -> str:
    """Get value from environment variable or prompt user interactively.

    Args:
        env_var: Environment variable name
        prompt: Prompt text for user
        default: Default value if user doesn't provide input

    Returns:
        Value from env var or user input
    """
    value = os.getenv(env_var)
    if value:
        return value

    if default:
        user_input = input(f"{prompt} [{default}]: ").strip()
        return user_input if user_input else default

    while True:
        user_input = input(f"{prompt}: ").strip()
        if user_input:
            return user_input
        print("This field is required. Please enter a value.")


def check_rest_connection(
    url: str, headers: dict[str, str] | None = None, timeout: int = 10
) -> bool:
    """Check if REST API endpoint is reachable.

    Args:
        url: API endpoint URL
        headers: Optional request headers
        timeout: Request timeout in seconds

    Returns:
        True if endpoint is reachable, False otherwise
    """
    try:
        response = requests.get(url, headers=headers or {}, timeout=timeout)
        return response.status_code < 500
    except Exception:
        return False


def check_ollama_connection(
    base_url: str = "http://localhost:11434",
) -> tuple[bool, list[str]]:
    """Test Ollama connection and return available models.

    Args:
        base_url: Ollama API base URL

    Returns:
        Tuple of (connected, list of model names)
    """
    try:
        response = requests.get(f"{base_url}/api/tags", timeout=5)
        if response.status_code == 200:
            data = response.json()
            models = [m["name"] for m in data.get("models", [])]
            return True, models
        return False, []
    except Exception:
        return False, []


def check_huggingface_model(model_name: str) -> tuple[bool, str]:
    """Check if HuggingFace model exists and is accessible.

    Args:
        model_name: HuggingFace model ID (e.g., "TinyLlama/TinyLlama-1.1B-Chat-v1.0")

    Returns:
        Tuple of (accessible, error message if not accessible)
    """
    try:
        from transformers import AutoTokenizer

        AutoTokenizer.from_pretrained(model_name, revision="main")
        return True, "Model accessible"
    except ImportError:
        return False, "transformers library not installed. Install with: pip install transformers"
    except Exception as e:
        return False, str(e)


def validate_model_file(path: str | Path) -> tuple[bool, str]:
    """Validate that model file exists and is readable.

    Args:
        path: Path to model file

    Returns:
        Tuple of (valid, error message if invalid)
    """
    path = Path(path)
    if not path.exists():
        return False, f"File not found: {path}"

    if not path.is_file():
        return False, f"Not a file: {path}"

    valid_extensions = [".gguf", ".bin", ".safetensors", ".ckpt", ".pth", ".pt"]
    if path.suffix not in valid_extensions:
        return (
            False,
            f"Unknown model format: {path.suffix}. Expected one of: {', '.join(valid_extensions)}",
        )

    if not os.access(path, os.R_OK):
        return False, f"File not readable: {path}"

    return True, "Model file valid"


def estimate_model_size(model_name: str) -> float:
    """Estimate model size in GB (rough approximation).

    Args:
        model_name: Model identifier (HuggingFace ID or local path)

    Returns:
        Estimated size in GB
    """
    # Rough estimates based on parameter count
    # Assumes 2 bytes per parameter (FP16) or 1 byte (INT8 quantized)
    size_estimates = {
        "tinyllama": 1.1 * 2 / 1024,  # 1.1B params * 2 bytes / 1024^3
        "phi3": 3.8 * 2 / 1024,
        "gemma": 2.0 * 2 / 1024,
        "qwen": 1.5 * 2 / 1024,
        "llama": 7.0 * 2 / 1024,
        "mistral": 7.0 * 2 / 1024,
    }

    model_lower = model_name.lower()
    for key, size_gb in size_estimates.items():
        if key in model_lower:
            return size_gb

    # Default estimate: assume 7B model
    return 14.0


def check_api_connection(
    url: str,
    headers: dict[str, str] | None = None,
    method: str = "GET",
    timeout: int = 10,
) -> tuple[bool, str]:
    """Test API connection with specific method.

    Args:
        url: API endpoint URL
        headers: Optional request headers
        method: HTTP method (GET, POST, etc.)
        timeout: Request timeout in seconds

    Returns:
        Tuple of (connected, error message if not connected)
    """
    try:
        if method.upper() == "GET":
            response = requests.get(url, headers=headers or {}, timeout=timeout)
        elif method.upper() == "POST":
            response = requests.post(url, headers=headers or {}, json={}, timeout=timeout)
        else:
            return False, f"Unsupported HTTP method: {method}"

        if response.status_code < 500:
            return True, f"Connection successful (status: {response.status_code})"
        return False, f"Server error (status: {response.status_code})"
    except requests.exceptions.ConnectionError as e:
        return False, f"Cannot connect to {url}: {e}"
    except requests.exceptions.Timeout:
        return False, f"Connection timeout after {timeout} seconds"
    except Exception as e:
        return False, f"Connection error: {e}"
