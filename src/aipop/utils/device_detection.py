"""Device detection utilities for GPU/CPU selection."""

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class DeviceInfo:
    """Information about the compute device."""

    device: str  # "cuda", "mps", or "cpu"
    device_name: str | None = None
    memory_gb: float | None = None
    cuda_version: str | None = None


def detect_device() -> str:
    """Detect available compute device.

    Returns:
        "cuda" if NVIDIA GPU available
        "mps" if Apple Silicon GPU available
        "cpu" otherwise
    """
    try:
        import torch

        if torch.cuda.is_available():
            return "cuda"
        elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
            return "mps"
        else:
            return "cpu"
    except ImportError:
        logger.warning("PyTorch not installed, defaulting to CPU")
        return "cpu"


def get_device_info() -> DeviceInfo:
    """Get detailed information about the compute device.

    Returns:
        DeviceInfo with device details
    """
    device = detect_device()

    if device == "cpu":
        return DeviceInfo(device="cpu", device_name="CPU")

    try:
        import torch

        if device == "cuda":
            device_name = torch.cuda.get_device_name(0)
            memory_gb = torch.cuda.get_device_properties(0).total_memory / (1024**3)
            cuda_version = torch.version.cuda

            return DeviceInfo(
                device="cuda",
                device_name=device_name,
                memory_gb=memory_gb,
                cuda_version=cuda_version,
            )

        elif device == "mps":
            return DeviceInfo(device="mps", device_name="Apple Silicon GPU")

    except Exception as e:
        logger.warning(f"Failed to get device info: {e}")

    return DeviceInfo(device=device)


def get_recommended_batch_size(device: str, model_size_gb: float = 7.0) -> int:
    """Get recommended batch size based on device.

    Args:
        device: Device type ("cuda", "mps", "cpu")
        model_size_gb: Estimated model size in GB

    Returns:
        Recommended batch size
    """
    if device == "cuda":
        info = get_device_info()
        if info.memory_gb:
            # Rule of thumb: leave 2GB for overhead, rest for batch
            available_gb = info.memory_gb - model_size_gb - 2.0
            if available_gb > 20:
                return 512  # High-end GPU (A100, H100)
            elif available_gb > 10:
                return 256  # Mid-range GPU (RTX 4090, A40)
            elif available_gb > 5:
                return 128  # Consumer GPU (RTX 3080, 4070)
            else:
                return 64  # Low-memory GPU
        return 256  # Default for CUDA

    elif device == "mps":
        return 64  # Apple Silicon - conservative

    else:  # CPU
        return 32  # Very conservative for CPU


def warn_if_cpu(operation: str = "GCG optimization") -> None:
    """Warn user if running on CPU.

    Args:
        operation: Description of the operation
    """
    device = detect_device()
    if device == "cpu":
        logger.warning(
            f"⚠️  Running {operation} on CPU. This will be SLOW. "
            f"Consider using a GPU for better performance."
        )
