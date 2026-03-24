-- Payload management database schema for AI Purple Ops
-- Stores custom payloads, SecLists imports, Git-synced payloads, and success tracking

-- Main payloads table
CREATE TABLE IF NOT EXISTS payloads (
    payload_id VARCHAR PRIMARY KEY,
    payload_text VARCHAR NOT NULL,
    category VARCHAR NOT NULL,  -- sqli, xss, path_traversal, command_injection, etc.
    source VARCHAR NOT NULL,     -- seclists, git, manual, mcp_exploits
    source_path VARCHAR,         -- Original file path or Git URL
    tool_name VARCHAR,           -- Tool this payload targets (e.g., read_file, search)
    description VARCHAR,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    tags JSON                    -- Additional tags ["waf_bypass", "unicode", etc.]
);

-- Payload success tracking
CREATE TABLE IF NOT EXISTS payload_success (
    success_id VARCHAR PRIMARY KEY,
    payload_id VARCHAR NOT NULL,
    engagement_id VARCHAR,       -- Link to engagements table
    tool_name VARCHAR NOT NULL,
    adapter_name VARCHAR NOT NULL,
    target_url VARCHAR,
    success BOOLEAN NOT NULL,
    response_snippet VARCHAR,    -- First 500 chars of response
    evidence_path VARCHAR,       -- Path to full evidence
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (payload_id) REFERENCES payloads(payload_id)
);

-- Payload sources metadata
CREATE TABLE IF NOT EXISTS payload_sources (
    source_id VARCHAR PRIMARY KEY,
    source_type VARCHAR NOT NULL,  -- seclists, git, file
    source_url VARCHAR,             -- Git URL or file path
    last_synced TIMESTAMP,
    total_payloads INTEGER DEFAULT 0,
    metadata JSON                   -- Version, branch, commit hash, etc.
);

-- Payload statistics view
CREATE VIEW IF NOT EXISTS payload_stats AS
SELECT 
    p.payload_id,
    p.payload_text,
    p.category,
    p.tool_name,
    COUNT(ps.success_id) as total_attempts,
    SUM(CASE WHEN ps.success THEN 1 ELSE 0 END) as successes,
    ROUND(CAST(SUM(CASE WHEN ps.success THEN 1 ELSE 0 END) AS FLOAT) / 
          NULLIF(COUNT(ps.success_id), 0) * 100, 2) as success_rate
FROM payloads p
LEFT JOIN payload_success ps ON p.payload_id = ps.payload_id
GROUP BY p.payload_id, p.payload_text, p.category, p.tool_name;

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_payloads_category ON payloads(category);
CREATE INDEX IF NOT EXISTS idx_payloads_tool ON payloads(tool_name);
CREATE INDEX IF NOT EXISTS idx_payloads_source ON payloads(source);
CREATE INDEX IF NOT EXISTS idx_payload_success_engagement ON payload_success(engagement_id);
CREATE INDEX IF NOT EXISTS idx_payload_success_payload ON payload_success(payload_id);

