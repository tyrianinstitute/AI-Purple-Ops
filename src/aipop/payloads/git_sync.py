"""Git repository synchronization for custom payload libraries.

Clones/pulls Git repos containing custom payloads and discovers payload files.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class GitSync:
    """Sync payloads from Git repositories.

    Features:
    - Clone Git repos with custom payloads
    - Pull updates on subsequent syncs
    - Auto-discover payload files (.txt, .list, .payloads)
    - Track commit hashes for versioning

    Example:
        >>> sync = GitSync(
        ...     repo_url="https://github.com/user/custom-payloads",
        ...     branch="main"
        ... )
        >>> payload_files = sync.sync_and_discover()
        >>> print(f"Found {len(payload_files)} payload files")
    """

    PAYLOAD_EXTENSIONS = [".txt", ".list", ".payloads", ".wordlist"]

    def __init__(
        self,
        repo_url: str,
        branch: str = "main",
        local_dir: Path | str | None = None,
    ) -> None:
        """Initialize Git sync.

        Args:
            repo_url: Git repository URL
            branch: Branch to checkout
            local_dir: Local directory for cloned repo (default: out/payloads/git/<repo_name>)
        """
        self.repo_url = repo_url
        self.branch = branch

        # Extract repo name from URL
        repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")

        if local_dir is None:
            local_dir = Path("out/payloads/git") / repo_name

        self.local_dir = Path(local_dir)
        self.local_dir.parent.mkdir(parents=True, exist_ok=True)

        logger.info(f"Git sync initialized: {repo_url} -> {self.local_dir}")

    def sync_and_discover(self) -> list[Path]:
        """Clone/pull repo and discover payload files.

        Returns:
            List of discovered payload file paths
        """
        # Clone or pull
        if self.local_dir.exists() and (self.local_dir / ".git").exists():
            self._pull()
        else:
            self._clone()

        # Discover payload files
        return self._discover_payloads()

    def _clone(self) -> None:
        """Clones the Git repository."""
        try:
            logger.info(f"Cloning {self.repo_url}...")

            subprocess.run(
                ["git", "clone", "--branch", self.branch, self.repo_url, str(self.local_dir)],
                check=True,
                capture_output=True,
                text=True,
            )

            logger.info(f"Cloned successfully to {self.local_dir}")

        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Git clone failed: {e.stderr}") from e
        except FileNotFoundError:
            raise RuntimeError("Git not found. Please install Git.") from None

    def _pull(self) -> None:
        """Pulls latest changes from the repository."""
        try:
            logger.info(f"Pulling updates from {self.repo_url}...")

            # Fetch and pull
            subprocess.run(
                ["git", "-C", str(self.local_dir), "fetch"],
                check=True,
                capture_output=True,
                text=True,
            )

            subprocess.run(
                ["git", "-C", str(self.local_dir), "pull", "origin", self.branch],
                check=True,
                capture_output=True,
                text=True,
            )

            logger.info("Pulled successfully")

        except subprocess.CalledProcessError as e:
            logger.warning(f"Git pull failed: {e.stderr}")
            # Continue anyway, use existing files

    def _discover_payloads(self) -> list[Path]:
        """Discovers payload files in the repository.

        Returns:
            List of payload file paths
        """
        payload_files = []

        for ext in self.PAYLOAD_EXTENSIONS:
            for file in self.local_dir.rglob(f"*{ext}"):
                # Skip hidden files and directories
                if any(part.startswith(".") for part in file.parts):
                    continue

                payload_files.append(file)

        logger.info(f"Discovered {len(payload_files)} payload files")

        return payload_files

    def get_current_commit(self) -> str | None:
        """Gets current commit hash.

        Returns:
            Commit hash or None if not a Git repo
        """
        try:
            result = subprocess.run(
                ["git", "-C", str(self.local_dir), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            )
            return result.stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            return None

    def get_metadata(self) -> dict[str, Any]:
        """Gets repository metadata.

        Returns:
            Metadata dict with URL, branch, commit, etc.
        """
        return {
            "repo_url": self.repo_url,
            "branch": self.branch,
            "local_dir": str(self.local_dir),
            "commit_hash": self.get_current_commit(),
        }
