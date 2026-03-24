-- Fingerprinting and intelligence database schema for AI Purple Ops
-- Stores reconnaissance data about target LLM/AI systems

-- Main fingerprints table
CREATE TABLE IF NOT EXISTS fingerprints (
    fingerprint_id VARCHAR PRIMARY KEY,
    engagement_id VARCHAR,  -- Link to engagements table
    adapter_type VARCHAR NOT NULL,  -- openai, anthropic, mcp, custom, etc.
    target_url VARCHAR,
    model_detected VARCHAR,  -- e.g., "gpt-4-turbo", "claude-3-opus"
    model_confidence FLOAT,  -- 0.0-1.0 confidence in detection
    guardrails_detected JSON,  -- {content_filter: "...", prompt_guard: "...", ...}
    capabilities JSON,  -- {function_calling: true, streaming: true, ...}
    rate_limits JSON,  -- {rpm: 60, tpm: 90000, burst: 10}
    vulnerabilities JSON,  -- List of detected vulnerabilities
    fingerprinted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata JSON  -- Additional fingerprinting data
);

-- Guardrail detection results
CREATE TABLE IF NOT EXISTS guardrail_detections (
    detection_id VARCHAR PRIMARY KEY,
    fingerprint_id VARCHAR NOT NULL,
    guardrail_type VARCHAR NOT NULL,  -- content_filter, prompt_guard, rate_limit, etc.
    detection_method VARCHAR,  -- probe, error_analysis, behavior_test
    confidence FLOAT,  -- 0.0-1.0
    evidence VARCHAR,  -- Sample response or error message
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (fingerprint_id) REFERENCES fingerprints(fingerprint_id)
);

-- Capability test results
CREATE TABLE IF NOT EXISTS capability_tests (
    test_id VARCHAR PRIMARY KEY,
    fingerprint_id VARCHAR NOT NULL,
    capability_name VARCHAR NOT NULL,  -- function_calling, json_mode, streaming, etc.
    test_result BOOLEAN,
    evidence VARCHAR,
    tested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (fingerprint_id) REFERENCES fingerprints(fingerprint_id)
);

-- Rate limit observations
CREATE TABLE IF NOT EXISTS rate_limit_observations (
    observation_id VARCHAR PRIMARY KEY,
    fingerprint_id VARCHAR NOT NULL,
    requests_sent INTEGER,
    time_window_seconds FLOAT,
    rate_limit_hit BOOLEAN,
    error_message VARCHAR,
    observed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (fingerprint_id) REFERENCES fingerprints(fingerprint_id)
);

-- Model detection attempts
CREATE TABLE IF NOT EXISTS model_detections (
    detection_id VARCHAR PRIMARY KEY,
    fingerprint_id VARCHAR NOT NULL,
    detection_technique VARCHAR,  -- token_pattern, error_signature, behavior_analysis
    detected_model VARCHAR,
    confidence FLOAT,
    evidence VARCHAR,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (fingerprint_id) REFERENCES fingerprints(fingerprint_id)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_fingerprints_engagement ON fingerprints(engagement_id);
CREATE INDEX IF NOT EXISTS idx_fingerprints_adapter ON fingerprints(adapter_type);
CREATE INDEX IF NOT EXISTS idx_guardrail_detections_fingerprint ON guardrail_detections(fingerprint_id);
CREATE INDEX IF NOT EXISTS idx_capability_tests_fingerprint ON capability_tests(fingerprint_id);
CREATE INDEX IF NOT EXISTS idx_rate_limit_obs_fingerprint ON rate_limit_observations(fingerprint_id);
CREATE INDEX IF NOT EXISTS idx_model_detections_fingerprint ON model_detections(fingerprint_id);

