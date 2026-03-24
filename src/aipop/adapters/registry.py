"""Adapter registry for built-in and custom adapters."""

from __future__ import annotations

import importlib
from typing import Any

from aipop.core.adapters import Adapter
from aipop.utils.adapter_paths import adapter_module_roots
from aipop.utils.errors import HarnessError


class AdapterRegistryError(HarnessError):
    """Error in adapter registry operations."""


class AdapterRegistry:
    """Registry for built-in and custom adapters."""

    _adapters: dict[str, type[Adapter]] = {}

    @classmethod
    def register(cls, name: str, adapter_class: type[Adapter]) -> None:
        """Register an adapter class.

        Args:
            name: Adapter name
            adapter_class: Adapter class implementing Adapter protocol

        Raises:
            AdapterRegistryError: If adapter is invalid
        """
        if not isinstance(adapter_class, type):
            raise AdapterRegistryError(f"Adapter must be a class, got {type(adapter_class)}")

        cls._adapters[name] = adapter_class

    @classmethod
    def get(cls, name: str, config: dict[str, Any] | None = None) -> Adapter:
        """Get adapter instance by name.

        Args:
            name: Adapter name
            config: Optional configuration for adapter

        Returns:
            Adapter instance

        Raises:
            AdapterRegistryError: If adapter not found or cannot be instantiated
        """
        # Check if already registered
        if name in cls._adapters:
            adapter_class = cls._adapters[name]
            return cls._instantiate(adapter_class, config or {})

        # Try to load custom adapter
        try:
            adapter_class = cls._load_custom_adapter(name)
            cls.register(name, adapter_class)
            return cls._instantiate(adapter_class, config or {})
        except Exception as e:
            raise AdapterRegistryError(
                f"Adapter '{name}' not found. Available: {list(cls._adapters.keys())}. Error: {e}"
            ) from e

    @classmethod
    def _load_custom_adapter(cls, name: str) -> type[Adapter]:
        """Load custom adapter from user code.

        Args:
            name: Adapter name (can be module path like 'user_adapters.huggingface')

        Returns:
            Adapter class

        Raises:
            AdapterRegistryError: If adapter cannot be loaded
        """
        # Try as module path (e.g., "user_adapters.huggingface")
        if "." in name:
            module_path, class_name = name.rsplit(".", 1)
            try:
                module = importlib.import_module(module_path)
                adapter_class = getattr(module, class_name)
                if not isinstance(adapter_class, type):
                    raise AdapterRegistryError(f"{name} is not a class, got {type(adapter_class)}")
                return adapter_class
            except (ImportError, AttributeError) as e:
                raise AdapterRegistryError(f"Failed to load adapter {name}: {e}") from e

        # Try as simple name in common locations
        common_paths = adapter_module_roots()

        for path in common_paths:
            try:
                module = importlib.import_module(f"{path}.{name}")
                # Look for class with same name (capitalized)
                class_name = name.replace("_", "").title().replace(" ", "")
                adapter_class = getattr(module, class_name, None)
                if adapter_class and isinstance(adapter_class, type):
                    return adapter_class
            except ImportError:
                continue

        raise AdapterRegistryError(f"Adapter '{name}' not found in common paths")

    @classmethod
    def _instantiate(cls, adapter_class: type[Adapter], config: dict[str, Any]) -> Adapter:
        """Instantiate adapter with config.

        Args:
            adapter_class: Adapter class
            config: Configuration dict

        Returns:
            Adapter instance

        Raises:
            AdapterRegistryError: If instantiation fails
        """
        try:
            # Try with config dict
            return adapter_class(**config)
        except TypeError:
            # Try without config
            try:
                return adapter_class()
            except Exception as e:
                raise AdapterRegistryError(
                    f"Failed to instantiate adapter {adapter_class.__name__}: {e}"
                ) from e

    @classmethod
    def list_adapters(cls) -> list[str]:
        """List all registered adapter names.

        Returns:
            List of adapter names
        """
        return list(cls._adapters.keys())


def load_adapter_from_yaml(config_path: str | Any) -> Adapter:
    """Load adapter from YAML config file.

    Enables quick adapter creation from Burp/cURL without writing Python code.

    Args:
        config_path: Path to YAML config file (str or Path object)

    Returns:
        CustomHTTPAdapter instance configured from YAML

    Raises:
        AdapterRegistryError: If config file doesn't exist or is invalid

    Example:
        >>> adapter = load_adapter_from_yaml("adapters/target_app.yaml")
        >>> response = adapter.invoke("Hello, world!")
    """
    from pathlib import Path

    import yaml

    from aipop.adapters.custom_http import CustomHTTPAdapter

    path = Path(config_path)

    if not path.exists():
        raise AdapterRegistryError(f"Adapter config not found: {config_path}")

    try:
        with path.open(encoding="utf-8") as f:
            config = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise AdapterRegistryError(f"Invalid YAML in {config_path}: {e}") from e

    if not config or not isinstance(config, dict):
        raise AdapterRegistryError(f"Invalid config format in {config_path}")

    return CustomHTTPAdapter(config)
