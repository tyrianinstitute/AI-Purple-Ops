# AIPOP Safety Hooks for Agent Operation

These hook configurations are designed for use with Claude Code or similar AI agents operating AIPOP.

## Setup

Copy the relevant hooks into your Claude Code settings:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [".aipop/hooks/pre-command-check.sh"]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [".aipop/hooks/post-command-log.sh"]
      }
    ]
  }
}
```

## What the hooks do

- `pre-command-check.sh`: Blocks destructive commands (rm -rf, git push --force) and validates the agent stays within scope
- `post-command-log.sh`: Logs every command the agent runs for audit trail

## Sandbox guidance

When running AIPOP via an AI agent, use OS-level sandboxing:

- Docker container with network restricted to target only
- Read-only mount for source code, writable mount for `out/` only
- No access to ~/.ssh, ~/.aws, or other credential stores
