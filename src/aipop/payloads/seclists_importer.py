"""SecLists wordlist importer for AI Purple Ops.

Imports payloads from SecLists (https://github.com/danielmiessler/SecLists)
by category with intelligent categorization and tool mapping.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class SecListsImporter:
    """Import SecLists wordlists with category mapping.

    SecLists structure:
    - Fuzzing/         → fuzzing, injection testing
    - Passwords/       → password lists
    - Discovery/       → content discovery
    - Payloads/        → exploitation payloads
    - Miscellaneous/   → various lists

    Example:
        >>> importer = SecListsImporter(seclists_path="/opt/SecLists")
        >>> payloads = importer.import_categories(["fuzzing", "payloads"])
        >>> print(f"Imported {len(payloads)} payloads")
    """

    # Category mappings: SecLists directory → AI Purple Ops category
    CATEGORY_MAPPINGS = {
        "fuzzing": ["Fuzzing"],
        "sqli": ["Fuzzing/SQL", "Payloads/SQL-Injection"],
        "xss": ["Fuzzing/XSS", "Payloads/XSS"],
        "path_traversal": ["Fuzzing/LFI", "Fuzzing/Path-Traversal"],
        "command_injection": ["Fuzzing/Command-Injection", "Payloads/Command-Injection"],
        "ssrf": ["Fuzzing/SSRF"],
        "passwords": ["Passwords"],
        "usernames": ["Usernames"],
        "discovery": ["Discovery"],
    }

    # Tool mappings: category → likely MCP tool
    TOOL_MAPPINGS = {
        "path_traversal": "read_file",
        "sqli": "search",
        "command_injection": "execute",
        "ssrf": "fetch_url",
    }

    def __init__(self, seclists_path: Path | str) -> None:
        """Initialize SecLists importer.

        Args:
            seclists_path: Path to SecLists directory
        """
        self.seclists_path = Path(seclists_path)

        if not self.seclists_path.exists():
            raise FileNotFoundError(f"SecLists path not found: {self.seclists_path}")

        logger.info(f"SecLists importer initialized: {self.seclists_path}")

    def import_categories(self, categories: list[str]) -> list[dict[str, Any]]:
        """Import SecLists wordlists by category.

        Args:
            categories: List of categories to import (e.g., ["fuzzing", "sqli"])
                       If empty, imports all

        Returns:
            List of payload dicts with text, category, source_path, etc.
        """
        payloads = []

        if not categories:
            # Import all categories
            categories = list(self.CATEGORY_MAPPINGS.keys())

        for category in categories:
            category_payloads = self._import_category(category)
            payloads.extend(category_payloads)
            logger.info(f"Imported {len(category_payloads)} payloads from category: {category}")

        return payloads

    def _import_category(self, category: str) -> list[dict[str, Any]]:
        """Import payloads for a single category.

        Args:
            category: Category to import

        Returns:
            List of payload dicts
        """
        payloads = []

        # Get directories for this category
        directories = self.CATEGORY_MAPPINGS.get(category, [])

        for directory in directories:
            dir_path = self.seclists_path / directory

            if not dir_path.exists():
                logger.warning(f"SecLists directory not found: {dir_path}")
                continue

            # Find all .txt files recursively
            for txt_file in dir_path.rglob("*.txt"):
                try:
                    file_payloads = self._parse_wordlist_file(txt_file, category)
                    payloads.extend(file_payloads)
                except Exception as e:
                    logger.warning(f"Failed to parse {txt_file}: {e}")

        return payloads

    def _parse_wordlist_file(self, file_path: Path, category: str) -> list[dict[str, Any]]:
        """Parse a wordlist file and extract payloads.

        Args:
            file_path: Path to wordlist file
            category: Category for these payloads

        Returns:
            List of payload dicts
        """
        payloads = []

        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()

                    # Skip empty lines and comments
                    if not line or line.startswith("#"):
                        continue

                    # Skip very long lines (likely not useful payloads)
                    if len(line) > 10000:
                        continue

                    payloads.append(
                        {
                            "text": line,
                            "category": category,
                            "source_path": str(file_path),
                            "tool_name": self.TOOL_MAPPINGS.get(category),
                            "tags": self._extract_tags(file_path, line),
                        }
                    )

        except Exception as e:
            logger.warning(f"Error reading {file_path}: {e}")

        return payloads

    def _extract_tags(self, file_path: Path, payload: str) -> list[str]:
        """Extract tags from file path and payload content.

        Args:
            file_path: Path to source file
            payload: Payload text

        Returns:
            List of tags
        """
        tags = []

        # Tags from file path
        path_lower = str(file_path).lower()

        if "waf" in path_lower:
            tags.append("waf_bypass")
        if "unicode" in path_lower:
            tags.append("unicode")
        if "encoded" in path_lower:
            tags.append("encoded")
        if "null" in path_lower or "byte" in path_lower:
            tags.append("null_byte")

        # Tags from payload content
        if "%2e%2e" in payload or "%252e" in payload:
            tags.append("url_encoded")
        if ".." in payload:
            tags.append("directory_traversal")
        if "'" in payload or '"' in payload:
            tags.append("quote_injection")
        if ";" in payload or "|" in payload or "&" in payload:
            tags.append("command_chaining")

        return tags

    def discover_available_categories(self) -> dict[str, list[str]]:
        """Discovers available SecLists categories.

        Returns:
            Dict of category -> list of directory paths
        """
        available = {}

        for category, directories in self.CATEGORY_MAPPINGS.items():
            found_dirs = []
            for directory in directories:
                dir_path = self.seclists_path / directory
                if dir_path.exists():
                    found_dirs.append(str(dir_path))

            if found_dirs:
                available[category] = found_dirs

        return available
