"""Payload import from Burp, wordlists, and previous runs.

Converts external payload sources into valid AIPOP suite YAML files.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml


def import_wordlist(wordlist_path: str | Path, output_path: str | Path,
                    category: str = "imported", risk: str = "medium",
                    expected: str = "refuse") -> Path:
    """Import payloads from a text wordlist (one per line)."""
    wordlist = Path(wordlist_path)
    lines = [l.strip() for l in wordlist.read_text().splitlines() if l.strip() and not l.startswith("#")]

    cases = []
    for i, line in enumerate(lines, 1):
        cases.append({
            "id": f"wl_{wordlist.stem}_{i:04d}",
            "prompt": line,
            "expected": expected,
            "metadata": {
                "category": category,
                "risk": risk,
                "source": f"wordlist:{wordlist.name}",
            },
        })

    suite = {
        "id": f"imported_{wordlist.stem}",
        "name": f"Imported from {wordlist.name}",
        "description": f"Payloads imported from wordlist: {wordlist.name} ({len(cases)} cases)",
        "cases": cases,
    }

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w") as f:
        yaml.dump(suite, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

    return output


def import_from_run(summary_path: str | Path, output_path: str | Path,
                    filter_type: str = "failed") -> Path:
    """Import payloads from a previous AIPOP run (summary.json)."""
    with Path(summary_path).open() as f:
        data = json.load(f)

    cases = []
    for result in data.get("results", []):
        if filter_type == "failed" and result.get("passed"):
            continue
        if filter_type == "passed" and not result.get("passed"):
            continue

        meta = result.get("metadata", {})
        cases.append({
            "id": f"retest_{result['test_id']}",
            "prompt": meta.get("prompt", result.get("test_id", "")),
            "expected": meta.get("expected", "refuse"),
            "metadata": {
                "category": meta.get("category", "retest"),
                "risk": meta.get("risk", "medium"),
                "source": f"retest:{data.get('run_id', 'unknown')}",
                "original_test_id": result["test_id"],
            },
        })

    suite = {
        "id": f"retest_{data.get('run_id', 'unknown')[:20]}",
        "name": f"Retest from {data.get('run_id', 'unknown')}",
        "description": f"Retesting {len(cases)} {filter_type} cases from previous run",
        "cases": cases,
    }

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w") as f:
        yaml.dump(suite, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

    return output


def import_burp(burp_path: str | Path, output_path: str | Path,
                category: str = "burp_import", risk: str = "high") -> Path:
    """Import payloads from Burp Suite XML export."""
    tree = ET.parse(str(burp_path))
    root = tree.getroot()

    cases = []
    for i, item in enumerate(root.findall(".//item"), 1):
        request_elem = item.find("request")
        if request_elem is None or not request_elem.text:
            continue

        # Extract the request body or URL as the prompt
        url_elem = item.find("url")
        url = url_elem.text if url_elem is not None else ""

        # Try to extract body from request
        request_text = request_elem.text
        body = ""
        if "\r\n\r\n" in request_text:
            body = request_text.split("\r\n\r\n", 1)[1]
        elif "\n\n" in request_text:
            body = request_text.split("\n\n", 1)[1]

        prompt = body if body else url

        if not prompt:
            continue

        cases.append({
            "id": f"burp_{i:04d}",
            "prompt": prompt,
            "expected": "refuse",
            "metadata": {
                "category": category,
                "risk": risk,
                "source": f"burp:{Path(burp_path).name}",
                "url": url,
            },
        })

    suite = {
        "id": "burp_import",
        "name": f"Imported from Burp ({Path(burp_path).name})",
        "description": f"Payloads imported from Burp export: {len(cases)} requests",
        "cases": cases,
    }

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w") as f:
        yaml.dump(suite, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

    return output
