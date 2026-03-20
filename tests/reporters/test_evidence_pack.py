"""Tests for evidence pack generation."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from aipop.core.gates import GateResult
from aipop.reporters.evidence_pack import EvidencePackError, EvidencePackGenerator


@pytest.fixture
def sample_summary(tmp_path: Path) -> Path:
    """Create a sample summary.json file."""
    summary_file = tmp_path / "summary.json"
    summary_data = {
        "run_id": "test-run-001",
        "total": 10,
        "passed": 9,
        "failed": 1,
        "results": [],
    }
    summary_file.write_text(json.dumps(summary_data), encoding="utf-8")
    return summary_file


@pytest.fixture
def sample_junit(tmp_path: Path) -> Path:
    """Create a sample junit.xml file."""
    junit_file = tmp_path / "junit.xml"
    junit_file.write_text('<?xml version="1.0"?><testsuite></testsuite>', encoding="utf-8")
    return junit_file


class TestEvidencePackGenerator:
    """Test evidence pack generation."""

    def test_generate_basic_pack(self, sample_summary: Path, tmp_path: Path) -> None:
        """Test generating a basic evidence pack with just summary."""
        generator = EvidencePackGenerator(tmp_path / "evidence")
        zip_path = generator.generate(
            run_id="test-run-001",
            summary_path=sample_summary,
            junit_path=None,
            transcripts_dir=None,
        )

        assert zip_path.exists()
        assert zip_path.suffix == ".zip"

        # Verify ZIP contents
        with zipfile.ZipFile(zip_path, "r") as zipf:
            files = zipf.namelist()
            assert "reports/summary.json" in files
            assert "evidence_manifest.json" in files

    def test_generate_with_junit(
        self, sample_summary: Path, sample_junit: Path, tmp_path: Path
    ) -> None:
        """Test generating evidence pack with JUnit XML."""
        generator = EvidencePackGenerator(tmp_path / "evidence")
        zip_path = generator.generate(
            run_id="test-run-001",
            summary_path=sample_summary,
            junit_path=sample_junit,
            transcripts_dir=None,
        )

        with zipfile.ZipFile(zip_path, "r") as zipf:
            files = zipf.namelist()
            assert "reports/summary.json" in files
            assert "reports/junit.xml" in files

    def test_generate_with_transcripts(self, sample_summary: Path, tmp_path: Path) -> None:
        """Test generating evidence pack with transcripts."""
        transcripts_dir = tmp_path / "transcripts"
        transcripts_dir.mkdir()
        (transcripts_dir / "test1.json").write_text('{"test": "data"}', encoding="utf-8")
        (transcripts_dir / "test2.json").write_text('{"test": "data2"}', encoding="utf-8")

        generator = EvidencePackGenerator(tmp_path / "evidence")
        zip_path = generator.generate(
            run_id="test-run-001",
            summary_path=sample_summary,
            junit_path=None,
            transcripts_dir=transcripts_dir,
        )

        with zipfile.ZipFile(zip_path, "r") as zipf:
            files = zipf.namelist()
            assert "transcripts/test1.json" in files
            assert "transcripts/test2.json" in files

    def test_generate_with_gate_result(self, sample_summary: Path, tmp_path: Path) -> None:
        """Test generating evidence pack with gate result."""
        gate_result = GateResult(
            passed=True,
            reason="All thresholds met",
            metrics={"harmful_output_rate": 0.0},
        )

        generator = EvidencePackGenerator(tmp_path / "evidence")
        zip_path = generator.generate(
            run_id="test-run-001",
            summary_path=sample_summary,
            junit_path=None,
            transcripts_dir=None,
            gate_result=gate_result,
            metrics={"harmful_output_rate": 0.0},
        )

        # Verify manifest includes gate result
        with zipfile.ZipFile(zip_path, "r") as zipf:
            manifest_data = json.loads(zipf.read("evidence_manifest.json"))
            assert "gate_result" in manifest_data
            assert manifest_data["gate_result"]["passed"] is True
            assert "metrics" in manifest_data

    def test_nonexistent_summary_raises_error(self, tmp_path: Path) -> None:
        """Test that nonexistent summary raises error."""
        generator = EvidencePackGenerator(tmp_path / "evidence")
        with pytest.raises(EvidencePackError, match="Summary file not found"):
            generator.generate(
                run_id="test-run-001",
                summary_path=tmp_path / "nonexistent.json",
            )

    def test_manifest_structure(self, sample_summary: Path, tmp_path: Path) -> None:
        """Test that manifest has correct structure."""
        generator = EvidencePackGenerator(tmp_path / "evidence")
        zip_path = generator.generate(
            run_id="test-run-001",
            summary_path=sample_summary,
        )

        with zipfile.ZipFile(zip_path, "r") as zipf:
            manifest_data = json.loads(zipf.read("evidence_manifest.json"))

            assert "run_id" in manifest_data
            assert manifest_data["run_id"] == "test-run-001"
            assert "timestamp" in manifest_data
            assert "artifacts" in manifest_data
            assert isinstance(manifest_data["artifacts"], list)
