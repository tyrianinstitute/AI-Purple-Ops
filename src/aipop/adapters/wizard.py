"""Interactive adapter setup wizard."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aipop.adapters.connection_helpers import (
    check_huggingface_model,
    check_ollama_connection,
    validate_model_file,
)

TEMPLATES = {
    "openai": "OpenAI API (or compatible)",
    "ollama": "Local Ollama model",
    "huggingface": "Local HuggingFace model",
    "llamacpp": "llama.cpp (GGUF format)",
    "custom_api": "Custom REST API endpoint",
    "custom": "Custom adapter (advanced)",
}


def run_wizard(output_dir: Path = Path("user_adapters")) -> dict[str, Any]:
    """Run interactive adapter creation wizard.

    Args:
        output_dir: Directory to save generated adapter files

    Returns:
        Dictionary with adapter configuration
    """
    print("\n🔌 AI Purple Ops - Adapter Setup Wizard\n")
    print("This wizard will help you create an adapter for your AI model.")
    print("You'll be asked a few questions about how to connect to your model.\n")

    # Step 1: Choose template
    print("What type of model are you connecting to?")
    template_list = list(TEMPLATES.items())
    for i, (key, desc) in enumerate(template_list, 1):
        print(f"  {i}. {desc} ({key})")

    choice = input("\nEnter number or template name: ").strip().lower()

    # Map choice to template
    if choice.isdigit():
        try:
            template_key = template_list[int(choice) - 1][0]
        except (ValueError, IndexError):
            print("Invalid choice, using 'custom'")
            template_key = "custom"
    else:
        template_key = choice if choice in TEMPLATES else "custom"

    print(f"\nSelected: {TEMPLATES.get(template_key, 'Custom adapter')}")

    # Step 2: Get adapter name
    adapter_name = input("\nAdapter name (e.g., 'my_model'): ").strip()
    if not adapter_name:
        adapter_name = "custom_adapter"

    # Step 3: Template-specific questions
    config = _gather_template_config(template_key)
    config["adapter_name"] = adapter_name
    config["template"] = template_key

    # Step 4: Test connection (if applicable)
    if template_key in ["ollama", "huggingface", "llamacpp"]:
        test = input("\nTest connection now? (y/n): ").strip().lower()
        if test == "y":
            _test_adapter_connection(template_key, config)

    return config


def _gather_template_config(template_key: str) -> dict[str, Any]:
    """Gather configuration for specific template.

    Args:
        template_key: Template identifier

    Returns:
        Configuration dictionary
    """
    config: dict[str, Any] = {}

    if template_key == "openai":
        config["base_url"] = (
            input("API base URL [https://api.openai.com/v1]: ").strip()
            or "https://api.openai.com/v1"
        )
        config["model"] = input("Model name [gpt-3.5-turbo]: ").strip() or "gpt-3.5-turbo"
        print("\n💡 API key will be read from OPENAI_API_KEY environment variable")

    elif template_key == "ollama":
        config["base_url"] = (
            input("Ollama URL [http://localhost:11434]: ").strip() or "http://localhost:11434"
        )
        config["model"] = input("Model name (e.g., tinyllama): ").strip() or "tinyllama"

    elif template_key == "huggingface":
        config["model_name"] = input(
            "HuggingFace model ID (e.g., TinyLlama/TinyLlama-1.1B-Chat-v1.0): "
        ).strip()
        if not config["model_name"]:
            config["model_name"] = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
        config["device"] = input("Device [cpu]: ").strip() or "cpu"

    elif template_key == "llamacpp":
        config["model_path"] = input("Path to .gguf model file: ").strip()

    elif template_key == "custom_api":
        config["endpoint"] = input("API endpoint URL: ").strip()
        config["method"] = input("HTTP method [POST]: ").strip() or "POST"
        auth_type = input("Authentication type (none/bearer/api_key) [none]: ").strip() or "none"
        if auth_type != "none":
            config["auth_type"] = auth_type
            config["auth_key"] = input(f"{auth_type} key/env var name: ").strip()

    return config


def _test_adapter_connection(template_key: str, config: dict[str, Any]) -> None:
    """Test adapter connection.

    Args:
        template_key: Template identifier
        config: Adapter configuration
    """
    print(f"\nTesting {template_key} connection...")

    if template_key == "ollama":
        base_url = config.get("base_url", "http://localhost:11434")
        model = config.get("model", "tinyllama")
        connected, models = check_ollama_connection(base_url)
        if connected:
            if model in models:
                print(f"✅ Connection successful! Model '{model}' is available.")
            else:
                print(f"⚠️  Ollama is running, but model '{model}' not found.")
                print(f"Available models: {', '.join(models) if models else 'none'}")
                print(f"Pull it with: ollama pull {model}")
        else:
            print("❌ Cannot connect to Ollama.")
            print("Start it with: ollama serve")

    elif template_key == "huggingface":
        model_name = config.get("model_name", "")
        if model_name:
            accessible, error_msg = check_huggingface_model(model_name)
            if accessible:
                print(f"✅ Model '{model_name}' is accessible.")
            else:
                print(f"❌ Cannot access model: {error_msg}")

    elif template_key == "llamacpp":
        model_path = config.get("model_path", "")
        if model_path:
            valid, error_msg = validate_model_file(model_path)
            if valid:
                print(f"✅ Model file is valid: {model_path}")
            else:
                print(f"❌ Invalid model file: {error_msg}")


def generate_adapter_file(config: dict[str, Any], output_dir: Path) -> Path:
    """Generate adapter file from template.

    Args:
        config: Adapter configuration from wizard
        output_dir: Directory to save adapter file

    Returns:
        Path to generated adapter file
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    adapter_name = config.get("adapter_name", "custom_adapter")
    template_key = config.get("template", "custom")

    # Generate Python code based on template
    code = _generate_adapter_code(template_key, config)

    # Write adapter file
    adapter_file = output_dir / f"{adapter_name}.py"
    adapter_file.write_text(code, encoding="utf-8")

    # Create __init__.py if it doesn't exist
    init_file = output_dir / "__init__.py"
    if not init_file.exists():
        init_file.write_text('"""User-defined adapters."""\n', encoding="utf-8")

    return adapter_file


def _generate_adapter_code(template_key: str, config: dict[str, Any]) -> str:
    """Generate adapter Python code from template.

    Args:
        template_key: Template identifier
        config: Adapter configuration

    Returns:
        Python code as string
    """
    adapter_name = config.get("adapter_name", "CustomAdapter")
    class_name = "".join(word.capitalize() for word in adapter_name.split("_")) + "Adapter"

    if template_key == "ollama":
        return f'''"""Ollama adapter for {adapter_name}."""

from __future__ import annotations

import time
from typing import Any

import requests

from aipop.core.models import ModelResponse
from aipop.adapters.connection_helpers import test_ollama_connection


class {class_name}:
    """Adapter for local Ollama model: {config.get("model", "unknown")}."""

    def __init__(
        self,
        model: str = "{config.get("model", "tinyllama")}",
        base_url: str = "{config.get("base_url", "http://localhost:11434")}",
        timeout: int = 120,
        **kwargs: Any,
    ) -> None:
        """Initialize Ollama adapter."""
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

        # Test connection
        connected, available_models = test_ollama_connection(self.base_url)
        if not connected:
            raise RuntimeError(
                f"Ollama not running at {{self.base_url}}\\n"
                f"Start it with: ollama serve"
            )

        if model not in available_models:
            raise RuntimeError(
                f"Model '{{model}}' not found. Pull it with: ollama pull {{model}}"
            )

    def invoke(self, prompt: str, **kwargs: Any) -> ModelResponse:
        """Invoke Ollama model."""
        start_time = time.time()

        url = f"{{self.base_url}}/api/generate"
        payload = {{
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {{
                "temperature": kwargs.get("temperature", 0.7),
                "num_predict": kwargs.get("max_tokens", 512),
            }},
        }}

        response = requests.post(url, json=payload, timeout=self.timeout)
        response.raise_for_status()
        data = response.json()

        latency_ms = (time.time() - start_time) * 1000
        response_text = data.get("response", "")

        prompt_tokens = len(prompt.split())
        completion_tokens = len(response_text.split())

        return ModelResponse(
            text=response_text,
            meta={{
                "model": self.model,
                "tokens": prompt_tokens + completion_tokens,
                "tokens_prompt": prompt_tokens,
                "tokens_completion": completion_tokens,
                "latency_ms": round(latency_ms, 2),
                "cost_usd": 0.0,
                "finish_reason": data.get("done_reason", "stop"),
            }},
        )
'''

    elif template_key == "openai":
        return f'''"""OpenAI-compatible API adapter for {adapter_name}."""

from __future__ import annotations

import os
import time
from typing import Any

import requests

from aipop.core.models import ModelResponse


class {class_name}:
    """Adapter for OpenAI-compatible API."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = "{config.get("base_url", "https://api.openai.com/v1")}",
        model: str = "{config.get("model", "gpt-3.5-turbo")}",
        timeout: int = 60,
        **kwargs: Any,
    ) -> None:
        """Initialize OpenAI-compatible adapter."""
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY environment variable not set")

        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def invoke(self, prompt: str, **kwargs: Any) -> ModelResponse:
        """Invoke model via OpenAI-compatible API."""
        start_time = time.time()

        url = f"{{self.base_url}}/chat/completions"
        headers = {{
            "Authorization": f"Bearer {{self.api_key}}",
            "Content-Type": "application/json",
        }}
        payload = {{
            "model": self.model,
            "messages": [{{"role": "user", "content": prompt}}],
            "temperature": kwargs.get("temperature", 0.7),
            "max_tokens": kwargs.get("max_tokens", 512),
        }}

        response = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
        response.raise_for_status()
        data = response.json()

        latency_ms = (time.time() - start_time) * 1000
        response_text = data["choices"][0]["message"]["content"]

        usage = data.get("usage", {{}})
        prompt_tokens = usage.get("prompt_tokens", 0)
        completion_tokens = usage.get("completion_tokens", 0)

        return ModelResponse(
            text=response_text,
            meta={{
                "model": self.model,
                "tokens": prompt_tokens + completion_tokens,
                "tokens_prompt": prompt_tokens,
                "tokens_completion": completion_tokens,
                "latency_ms": round(latency_ms, 2),
                "cost_usd": 0.0,
                "finish_reason": data["choices"][0].get("finish_reason", "stop"),
            }},
        )
'''

    # Add more templates as needed...

    # Default custom template
    return f'''"""Custom adapter for {adapter_name}."""

from __future__ import annotations

from typing import Any

from aipop.core.models import ModelResponse


class {class_name}:
    """Custom adapter implementation."""

    def __init__(self, **kwargs: Any) -> None:
        """Initialize custom adapter."""
        # TODO: Add your initialization code here
        pass

    def invoke(self, prompt: str, **kwargs: Any) -> ModelResponse:
        """Invoke model and return response."""
        # TODO: Implement your model invocation logic
        return ModelResponse(
            text="Custom adapter response",
            meta={{
                "model": "custom",
                "tokens": 0,
                "latency_ms": 0,
                "cost_usd": 0.0,
            }},
        )
'''
