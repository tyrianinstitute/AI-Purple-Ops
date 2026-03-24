#!/bin/bash
# Post-command audit logger for AI agent operation of AIPOP
# Logs every command to .aipop/agent_audit.log

LOG_FILE=".aipop/agent_audit.log"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "${TIMESTAMP} | ${*}" >> "$LOG_FILE"
