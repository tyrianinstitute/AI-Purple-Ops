#!/bin/bash
# Pre-command safety check for AI agent operation of AIPOP
# Blocks destructive commands and validates scope

COMMAND="$*"

# Block destructive operations
BLOCKED_PATTERNS=(
    "rm -rf"
    "git push"
    "git reset --hard"
    "git checkout -- ."
    "chmod 777"
    "curl.*| bash"
    "wget.*| bash"
    "eval "
    "sudo "
)

for pattern in "${BLOCKED_PATTERNS[@]}"; do
    if echo "$COMMAND" | grep -qiE "$pattern"; then
        echo "BLOCKED: Command matches blocked pattern: $pattern" >&2
        exit 1
    fi
done

# Allow the command
exit 0
