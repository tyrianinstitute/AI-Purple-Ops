#!/bin/bash
# LinkedIn demo — the money shot
# Shows: indirect injection via document upload against a real target
# One command. Real finding. Credentials leaked.

export TERM=xterm-256color
cd /home/tyrian/code/AI-Purple-Ops

type_cmd() {
    local cmd="$1"
    for (( i=0; i<${#cmd}; i++ )); do
        printf '%s' "${cmd:$i:1}"
        sleep 0.03
    done
    echo ""
    sleep 0.3
}

clear
sleep 0.5

# Set the scene
printf '\033[1;35m# aipop — AI security testing in one command\033[0m\n'
printf '\033[2m# target: RAG chatbot accepting document uploads\033[0m\n'
sleep 1.5

# The one-liner
printf '\n\033[1;35m$\033[0m '
type_cmd "aipop scan http://localhost:8000 --suite indirect/upload_poison"
sleep 0.3

# Run it for real
aipop scan http://localhost:8000 --suite indirect/upload_poison --skip-recon

sleep 4
