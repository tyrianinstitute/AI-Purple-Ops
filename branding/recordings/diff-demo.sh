#!/bin/bash
# Diff demo: Purple team — show before/after defense comparison
# Run with: asciinema rec --command="bash branding/recordings/diff-demo.sh" branding/recordings/diff-demo.cast

type_cmd() {
    local cmd="$1"
    for (( i=0; i<${#cmd}; i++ )); do
        printf '%s' "${cmd:$i:1}"
        sleep 0.04
    done
    echo ""
    sleep 0.3
}

clear
sleep 1

printf '\033[1;35m# Purple team: measure defense effectiveness\033[0m\n'
printf '\033[1;35m# Scan BEFORE defenses, scan AFTER, diff the results\033[0m\n'
sleep 1.5

printf '\n\033[1;35m$\033[0m '
type_cmd "aipop diff out/reports/before-defenses.json out/reports/after-defenses.json"
cd /home/tyrian/code/AI-Purple-Ops
# Use whatever summary files exist from previous runs
if [ -f out/reports/summary.json ]; then
    cp out/reports/summary.json /tmp/before.json 2>/dev/null
    aipop diff /tmp/before.json out/reports/summary.json 2>&1
else
    echo "Run hero-scan.sh first to generate results"
fi
sleep 3
