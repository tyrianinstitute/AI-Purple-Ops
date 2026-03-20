# Core Interfaces

This directory contains Protocol definitions for the 9 utility layers of the AI Purple Ops evaluation framework.

## Architecture Overview

The framework is organized into distinct layers, each with a specific purpose and analogy to traditional security tooling:

| Layer                 | Purpose               | Analogy                     | Status      | Branch |
| --------------------- | --------------------- | --------------------------- | ----------- | ------ |
| **Adapters**          | Model I/O abstraction | Device driver               | Protocol ✓  | b04    |
| **Probes**            | Active test payloads  | Unit test / exploit payload | Placeholder | b07    |
| **Detectors**         | Output analysis       | IDS or static analyzer      | Placeholder | b05    |
| **Evaluators**        | Scoring logic         | Assertions / metrics        | Placeholder | b05    |
| **Orchestrators**     | Execution logic       | CI/CD controller            | Protocol ✓  | b04    |
| **Metrics & Logging** | Observability         | SIEM / telemetry backend    | Protocol ✓  | b04    |
| **Policy Layer**      | Rule definitions      | Policy-as-code              | Placeholder | b05    |
| **Mutators/Fuzzers**  | Input diversification | Fuzzer engine               | Placeholder | b07    |
| **Exploit Builders**  | Chain vulnerabilities | Post-exploitation toolkit   | Placeholder | --     |

## Current State (b03)

### ✅ Protocols Defined
The following interfaces are ready for b04 implementation:

- **`Adapter`** (adapters.py) - Model I/O abstraction, returns ModelResponse
- **`Runner`** (runners.py) - Test execution orchestration, supports batch execution
- **`Reporter`** (reporters.py) - Result serialization with streaming support
- **`ModelResponse`** (models.py) - Model response with text + metadata (tokens, cost, latency)
- **`TestCase`** (models.py) - Test case data model
- **`RunResult`** (models.py) - Test result data model

### 🚧 Placeholders
The following files exist with TODO roadmaps for future branches:

- **`detectors.py`** - Output analysis protocols (b05)
- **`evaluators.py`** - Scoring and metrics protocols (b05)
- **`probes.py`** - Test payload generation protocols (b07)
- **`mutators.py`** - Input fuzzing protocols (b07)
- **`exploits.py`** - Attack chain protocols (not yet implemented)

## Usage

### Importing Core Interfaces

```python
from aipop.core import Adapter, ModelResponse, Runner, Reporter, TestCase, RunResult
```

### Example: Implementing an Adapter

```python
from typing import Any
from aipop.core import Adapter, ModelResponse

class MockAdapter:
    """Mock adapter for deterministic testing."""

    def invoke(self, prompt: str, **kwargs: Any) -> ModelResponse:
        return ModelResponse(
            text=f"Mock response to: {prompt}",
            meta={"tokens": 10, "latency_ms": 50, "model": "mock"}
        )
```

### Example: Implementing a Runner

```python
from typing import Iterator
from aipop.core import Runner, TestCase, RunResult, Adapter

class MockRunner:
    """Mock runner that executes test cases."""

    def __init__(self, adapter: Adapter) -> None:
        self.adapter = adapter

    def execute(self, test_case: TestCase) -> RunResult:
        model_response = self.adapter.invoke(test_case.prompt)
        return RunResult(
            test_id=test_case.id,
            response=model_response.text,
            passed=True,
            metadata=test_case.metadata,
        )

    def execute_many(self, cases: list[TestCase]) -> Iterator[RunResult]:
        for case in cases:
            yield self.execute(case)
```

## Design Principles

1. **Protocol-First**: All layers use Python `Protocol` for structural typing
2. **Minimal Signatures**: Interfaces define only what's needed, expand later
3. **TODO-Driven**: Each protocol includes TODO comments linking to branches
4. **Branch-Aligned**: Implementation matches the 10-phase roadmap (b01-b10)
5. **Type-Safe**: Full type hints with mypy strict mode compliance

## Roadmap

### Phase b04 (Mock Runner)
- Implement `MockAdapter` for deterministic testing
- Implement `MockRunner` for test execution
- Implement `JSONReporter` and `JUnitReporter`
- Create sample `TestCase` fixtures in `suites/normal/`

### Phase b05 (Oracles and Policies)
- Define `Detector` protocol
- Implement `HarmfulContentDetector`
- Define `Evaluator` protocol
- Implement `ThresholdEvaluator` for SLO checks
- Expand `TestCase` with `expected_policy` field
- Expand `RunResult` with `policy_violations` field

### Phase b06 (Gates and Evidence)
- Expand `Runner` with gate threshold checks
- Expand `RunResult` with `evidence_links` field
- Implement evidence pack generation

### Phase b07 (Adversarial Suites)
- Define `Probe` protocol
- Implement prompt injection, RAG, and UI probes
- Define `Mutator` protocol
- Integrate Hypothesis for property-based fuzzing
- Expand `TestCase` with `attack_type` field

### Tool Simulation (not yet implemented)
- Define `ExploitBuilder` protocol
- Implement tool chain exploits
- Implement RAG security features
- Add streaming support to `Adapter`
- Add tool call support to `Adapter`

### CI/CD Integration (not yet implemented)
- Expand `Reporter` with CI/CD status checks
- Implement GitHub Actions integration

## See Also

- [docs/architecture/pipeline.md](../../../docs/architecture/pipeline.md) - End-to-end evaluation lifecycle
