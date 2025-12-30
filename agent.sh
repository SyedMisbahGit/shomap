#!/usr/bin/env bash
set -u

# --- [CONFIGURATION DEFAULTS] ---
# Default to Fast/Mini
AI_MODEL="gpt-4o-mini"
AI_TIMEOUT="120"
PRICE_INPUT_1M=0.15
PRICE_OUTPUT_1M=0.60
MAX_RECURSION_LOOPS=2

# Visual Styles
BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
GREY='\033[0;90m'
NC='\033[0m'

# --- [GLOBAL INIT] ---
TARGET=""
ORG="Unknown"
PORTS=""
SCAN_STATUS="Active"
RISK_LEVEL="Low"
REMEDIATION_PLAN=""
SOFTWARE_DETECTED="Unknown"
VERSION_DETECTED=""
CIPHER_SUITES="Not Checked"
OS_NMAP="Unknown"
CVES_LIST=""
CVES_COUNT=0
SHODAN_CVES_CONTEXT="None"
TMPDIR=""
HAS_NUCLEI="false"
NUCLEI_HITS="Skipped"
NUCLEI_BIN="nuclei"
AI_DISPARITY_LOG=""
AI_VERIFICATION_LOG=""

# Accounting Globals
SHODAN_QUERIES=0
OPENAI_INPUT_TOKENS=0
OPENAI_OUTPUT_TOKENS=0

# Safe Cleanup Trap
cleanup() {
    if [[ -n "${TMPDIR:-}" ]] && [[ -d "$TMPDIR" ]]; then
        rm -rf "$TMPDIR"
    fi
}
trap cleanup EXIT

# Dependency Check
for cmd in curl jq nmap xmllint openssl timeout wget tar unzip awk; do
  command -v "$cmd" >/dev/null || { echo -e "${RED}[!] Missing critical dependency: $cmd${NC}"; exit 1; }
done

# --- [AUTH HANDLER] ---
if [[ -z "${OPENAI_API_KEY:-}" ]]; then
    echo -e "${YELLOW}[!] OPENAI_API_KEY not found.${NC}"
    read -rsp "Enter OpenAI API Key: " INPUT_OPENAI
    export OPENAI_API_KEY=$(echo "$INPUT_OPENAI" | xargs)
    echo ""
fi

if [[ -z "${SHODAN_API_KEY:-}" ]]; then
    echo -e "${YELLOW}[!] SHODAN_API_KEY not found.${NC}"
    read -rsp "Enter Shodan API Key: " INPUT_SHODAN
    export SHODAN_API_KEY=$(echo "$INPUT_SHODAN" | xargs)
    echo ""
fi

# --- [INPUT VALIDATION] ---
if [[ $# -eq 0 ]]; then 
    read -rp "Enter Target IP: " TARGET
else 
    TARGET=$1
fi

TARGET=$(echo "$TARGET" | xargs)
if [[ "$TARGET" =~ [,\ ] ]]; then
    echo -e "${RED}[!] ERROR: Multiple IPs detected.${NC}"
    echo -e "${RED}[!] This script is architected for a SINGLE target only.${NC}"
    exit 1
fi

if [[ -z "$TARGET" ]]; then
    echo -e "${RED}[!] ERROR: Target cannot be empty.${NC}"
    exit 1
fi

# --- [MODEL SELECTION] ---
echo -e "\n${CYAN}Select AI Reasoning Model:${NC}"
echo -e "  1) ${GREEN}Fast & Economical${NC} (gpt-4o-mini) [~95% cheaper, good for general tasks]"
echo -e "  2) ${YELLOW}High Reliability${NC}  (gpt-4o)      [Expensive, best for complex logic]"
read -rp "Choice [1/2] (default: 1): " MODEL_CHOICE

if [[ "$MODEL_CHOICE" == "2" ]]; then
    AI_MODEL="gpt-4o"
    PRICE_INPUT_1M=2.50
    PRICE_OUTPUT_1M=10.00
    echo -e "-> Selected: ${YELLOW}gpt-4o${NC}"
else
    AI_MODEL="gpt-4o-mini"
    PRICE_INPUT_1M=0.15
    PRICE_OUTPUT_1M=0.60
    echo -e "-> Selected: ${GREEN}gpt-4o-mini${NC}"
fi

TMPDIR="$(mktemp -d)"
mkdir -p "$TMPDIR/bin"
export PATH="$TMPDIR/bin:$PATH"

# File Definitions
SHODAN_JSON="$TMPDIR/shodan.json"
NMAP_XML="$TMPDIR/nmap.xml"
WEB_HEADERS="$TMPDIR/web_headers.txt"
TECH_STACK_FILE="$TMPDIR/tech_stack.txt"
NUCLEI_LOG="$TMPDIR/nuclei.log"
AI_RESPONSE_FILE="$TMPDIR/ai_response.txt"
DISPARITY_LOG="$TMPDIR/disparity_scan.txt"
PARSED_SERVICES="$TMPDIR/parsed_services.txt"
CVE_SCAN_OUT="$TMPDIR/cve_scan_output.txt"

# --- [ROBUST NUCLEI INSTALLER] ---
if command -v nuclei >/dev/null; then
    HAS_NUCLEI="true"
else
    echo -e "${YELLOW}[!] Nuclei not found. Attempting dynamic install...${NC}"
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    if [[ "$ARCH" == "x86_64" ]]; then ARCH="amd64"; elif [[ "$ARCH" == "aarch64" ]]; then ARCH="arm64"; else ARCH="amd64"; fi
    
    LATEST_URL=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | jq -r ".assets[] | select(.name | contains(\"linux_${ARCH}.zip\")) | .browser_download_url" | head -n 1)
    
    if [[ -z "$LATEST_URL" || "$LATEST_URL" == "null" ]]; then 
        LATEST_URL="https://github.com/projectdiscovery/nuclei/releases/download/v3.3.6/nuclei_3.3.6_linux_${ARCH}.zip"
    fi
    
    if curl -L -s "$LATEST_URL" -o "$TMPDIR/nuclei.zip"; then
        unzip -q "$TMPDIR/nuclei.zip" -d "$TMPDIR/bin" 2>/dev/null || true
        FOUND_BIN=$(find "$TMPDIR/bin" -type f -name "nuclei" | head -n 1)
        if [[ -f "$FOUND_BIN" ]]; then
            chmod +x "$FOUND_BIN"
            NUCLEI_BIN="$FOUND_BIN"
            HAS_NUCLEI="true"
            echo -e "    -> ${GREEN}Nuclei installed successfully.${NC}"
        else
            echo -e "    -> ${RED}[!] Binary not found after extraction.${NC}"
        fi
    else
        echo -e "    -> ${RED}[!] Download failed.${NC}"
    fi
fi

if [[ "$HAS_NUCLEI" == "true" ]]; then
    echo -e "    -> Updating Nuclei Templates..."
    "$NUCLEI_BIN" -update-templates -silent >/dev/null 2>&1 || true
fi

# --- [HELPER FUNCTIONS] ---
ask_openai_persist() {
    local system_prompt="$1"
    local user_prompt="$2"
    local max_retries=2
    local attempt=0
    > "$AI_RESPONSE_FILE"
    
    while [[ $attempt -le $max_retries ]]; do
        local payload
        payload=$(jq -n \
                  --arg model "$AI_MODEL" \
                  --arg sys "$system_prompt" \
                  --arg usr "$user_prompt" \
                  '{model: $model, messages: [{role: "system", content: $sys}, {role: "user", content: $usr}], temperature: 0.2}')

        local response
        response=$(curl -s --max-time "$AI_TIMEOUT" https://api.openai.com/v1/chat/completions \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $OPENAI_API_KEY" \
            -d "$payload")

        if echo "$response" | jq -e '.error' >/dev/null 2>&1; then
            local err_msg
            err_msg=$(echo "$response" | jq -r '.error.message')
            if [[ "$err_msg" =~ "quota" ]] || [[ "$err_msg" =~ "key" ]]; then
                echo -e "\n${RED}[!] OpenAI API Error: $err_msg${NC}"
                read -rsp "--> Enter a NEW working API Key (or Ctrl+C to abort): " OPENAI_API_KEY
                echo ""
                export OPENAI_API_KEY
                attempt=$((attempt+1))
                continue
            else
                echo "API_ERROR: $err_msg" > "$AI_RESPONSE_FILE"
                return
            fi
        else
            echo "$response" | jq -r '.choices[0].message.content' > "$AI_RESPONSE_FILE"
            local in_tok
            local out_tok
            in_tok=$(echo "$response" | jq -r '.usage.prompt_tokens // 0')
            out_tok=$(echo "$response" | jq -r '.usage.completion_tokens // 0')
            OPENAI_INPUT_TOKENS=$((OPENAI_INPUT_TOKENS + in_tok))
            OPENAI_OUTPUT_TOKENS=$((OPENAI_OUTPUT_TOKENS + out_tok))
            return
        fi
    done
}

echo -e "${CYAN}"
echo "=================================================================="
echo "   SENTINEL CORE v63.0 | Infrastructure Auditor | Target: $TARGET"
echo "=================================================================="
echo -e "${NC}"

sudo -v

# --- [PHASE 1] PASSIVE RECON (SUMMARIZED) ---
echo -e "\n${YELLOW}[+] Phase 1: Passive Intelligence (Shodan)${NC}"
curl -s "https://api.shodan.io/shodan/host/$TARGET?key=$SHODAN_API_KEY" -o "$SHODAN_JSON" || true
SHODAN_QUERIES=$((SHODAN_QUERIES + 1))

if [[ -s "$SHODAN_JSON" ]] && jq -e . "$SHODAN_JSON" >/dev/null 2>&1; then
    if jq -e '.error' "$SHODAN_JSON" >/dev/null 2>&1; then
        echo -e "    ${RED}x Shodan Error: $(jq -r '.error' "$SHODAN_JSON")${NC}"
    else
        ORG=$(jq -r '.org // "Unknown"' "$SHODAN_JSON")
        ISP=$(jq -r '.isp // "Unknown"' "$SHODAN_JSON")
        ASN=$(jq -r '.asn // "Unknown"' "$SHODAN_JSON")
        GEO="$(jq -r '.city // "Unknown"' "$SHODAN_JSON"), $(jq -r '.country_name // "Unknown"' "$SHODAN_JSON")"
        DOMAINS=$(jq -r '.domains[]?' "$SHODAN_JSON" | head -3 | tr '\n' ' ' || echo "None")
        PORTS=$(jq -r '.data[].port' "$SHODAN_JSON" 2>/dev/null | sort -nu | tr '\n' ',' | sed 's/,$//')
        OS_SHODAN=$(jq -r '.os // "Unknown"' "$SHODAN_JSON")
        LAST_UPDATE=$(jq -r '.last_update // "Unknown"' "$SHODAN_JSON" | cut -d'T' -f1)
        
        CVES_RAW=$(jq -r '.vulns[]?' "$SHODAN_JSON" 2>/dev/null || echo "")
        CVES_LIST="$CVES_RAW"
        CVES_COUNT=$(echo "$CVES_RAW" | wc -w)
        if [[ "$CVES_COUNT" -gt 0 ]]; then
            SHODAN_CVES_CONTEXT=$(echo "$CVES_RAW" | tr '\n' ' ')
        fi
        
        CVES_DISPLAY=$(echo "$CVES_RAW" | head -n 5 | tr '\n' ' ' | sed 's/ $//')
        [[ -z "$CVES_DISPLAY" ]] && CVES_DISPLAY="None"
        
        echo -e "${BOLD}TABLE: passive_recon_summary${NC}"
        echo -e "${CYAN}+----------------------+--------------------------------------------------+${NC}"
        printf "${CYAN}|${NC} %-20s ${CYAN}|${NC} %-48s ${CYAN}|${NC}\n" "Organization" "${ORG:0:48}"
        printf "${CYAN}|${NC} %-20s ${CYAN}|${NC} %-48s ${CYAN}|${NC}\n" "ISP / ASN" "${ISP:0:20} / ${ASN:0:20}"
        printf "${CYAN}|${NC} %-20s ${CYAN}|${NC} %-48s ${CYAN}|${NC}\n" "Location" "${GEO:0:48}"
        printf "${CYAN}|${NC} %-20s ${CYAN}|${NC} %-48s ${CYAN}|${NC}\n" "OS (Passive)" "${OS_SHODAN:0:48}"
        printf "${CYAN}|${NC} %-20s ${CYAN}|${NC} %-48s ${CYAN}|${NC}\n" "Domains" "${DOMAINS:0:48}"
        printf "${CYAN}|${NC} %-20s ${CYAN}|${NC} %-48s ${CYAN}|${NC}\n" "Last Update" "$LAST_UPDATE"
        
        if [[ "$CVES_COUNT" -gt 0 ]]; then
            printf "${CYAN}|${NC} %-20s ${CYAN}|${NC} ${RED}%-48s${NC} ${CYAN}|${NC}\n" "CVE Count" "$CVES_COUNT Potential"
            echo -e "${CYAN}|----------------------+--------------------------------------------------|${NC}"
            printf "${CYAN}|${NC} %-20s ${CYAN}|${NC} %-48s ${CYAN}|${NC}\n" "Top CVEs" "${CVES_DISPLAY}..."
        else
            printf "${CYAN}|${NC} %-20s ${CYAN}|${NC} ${GREEN}%-48s${NC} ${CYAN}|${NC}\n" "CVE Count" "0 Found"
        fi
        echo -e "${CYAN}+----------------------+--------------------------------------------------+${NC}"
    fi
else
    echo -e "    ${RED}[!] Invalid JSON response from Shodan.${NC}"
fi

# --- [PHASE 2] ACTIVE RECON ---
echo -e "\n${YELLOW}[+] Phase 2: Active Verification (Nmap Aggressive)${NC}"
if [[ -z "${PORTS:-}" ]]; then SCAN_ARGS="--top-ports 100"; else 
    # Prioritize common admin ports alongside historical ports
    ALL_PORTS=$(echo "$PORTS,80,443,8080,8443,3000,5000,21,22,3306,3389,5432,6379" | tr ',' '\n' | sort -nu | tr '\n' ',' | sed 's/,$//')
    SCAN_ARGS="-p $ALL_PORTS"
fi

echo -e "    -> Executing Nmap (Aggressive Mode)..."
sudo nmap -Pn -A -T4 -oX "$NMAP_XML" $SCAN_ARGS "$TARGET" | sed 's/^/    /g' || true

if [[ ! -s "$NMAP_XML" ]]; then
    echo -e "    ${RED}[!] Nmap Scan Failed or produced no output.${NC}"
    SCAN_STATUS="Blocked"
fi

OS_NMAP=$(xmllint --xpath '//osmatch/@name' "$NMAP_XML" 2>/dev/null | head -1 | cut -d'"' -f2 || echo "Unknown")

xmllint --xpath '//port[state/@state="open"]' "$NMAP_XML" 2>/dev/null | \
sed 's/<port/\n<port/g' | grep 'state="open"' > "$PARSED_SERVICES"

DETECTED_SERVICES=()
while read -r line; do
    if [[ -n "$line" ]]; then
        p=$(echo "$line" | sed -n 's/.*portid="\([^"]*\)".*/\1/p')
        s=$(echo "$line" | sed -n 's/.*service name="\([^"]*\)".*/\1/p')
        prod=$(echo "$line" | sed -n 's/.*product="\([^"]*\)".*/\1/p')
        v=$(echo "$line" | sed -n 's/.*version="\([^"]*\)".*/\1/p')
        script_out=$(echo "$line" | sed -n 's/.*<script id="http-title" output="\([^"]*\)".*/\1/p' | sed 's/&#10;//g' | cut -c 1-30)
        cpe=$(echo "$line" | sed -n 's/.*<cpe>\([^<]*\)<\/cpe>.*/\1/p' | cut -d':' -f2-4 || echo "N/A")
        
        FINAL_NAME="${prod:-$s}"
        FULL_VER="${v:-Unknown}"
        if [[ -n "$script_out" ]]; then FULL_VER="$FULL_VER [Title: $script_out]"; fi
        DETECTED_SERVICES+=("$p|$FINAL_NAME|$FULL_VER|${cpe}")
    fi
done < "$PARSED_SERVICES"

# Extract just the port numbers for later use
OPEN_PORTS_COMMA=$(echo "${DETECTED_SERVICES[@]}" | grep -o '^[0-9]\+' | tr '\n' ',' | sed 's/,$//')
if [[ -z "$OPEN_PORTS_COMMA" ]]; then OPEN_PORTS_COMMA="80,443"; fi

if [[ ${#DETECTED_SERVICES[@]} -eq 0 ]] && [[ -n "$PORTS" ]]; then
    SCAN_STATUS="Blocked"
    IFS=',' read -ra HIST_PORTS_ARRAY <<< "$PORTS"
    for p in "${HIST_PORTS_ARRAY[@]}"; do
        DETECTED_SERVICES+=("$p|tcpwrapped|Unknown|[History]|N/A")
    done
elif [[ ${#DETECTED_SERVICES[@]} -eq 0 ]]; then
    SCAN_STATUS="Blackout"
fi

echo -e "${BOLD}TABLE: active_scan_rich${NC}"
echo -e "${CYAN}+--------+----------+----------------------+------------------------------------------+${NC}"
printf "${CYAN}|${NC} %-6s ${CYAN}|${NC} %-8s ${CYAN}|${NC} %-20s ${CYAN}|${NC} %-40s ${CYAN}|${NC}\n" "PORT" "STATE" "SERVICE" "VERSION / CONTEXT"
echo -e "${CYAN}+--------+----------+----------------------+------------------------------------------+${NC}"

HAS_WEB="False"
if [[ ${#DETECTED_SERVICES[@]} -gt 0 ]]; then
    for entry in "${DETECTED_SERVICES[@]}"; do
        IFS='|' read -r p s v cpe <<< "$entry"
        if [[ "$s" == "tcpwrapped" ]]; then DISPLAY_SVC="${GREY}tcpwrapped${NC}"; else DISPLAY_SVC="${s:0:20}"; fi
        printf "${CYAN}|${NC} %-6s ${CYAN}|${NC} %-8s ${CYAN}|${NC} %-20b ${CYAN}|${NC} %-40s ${CYAN}|${NC}\n" "$p" "OPEN" "$DISPLAY_SVC" "${v:0:40}"
        if [[ "$s" =~ http ]] || [[ "$s" =~ awselb ]] || [[ "$p" =~ ^(80|443|8080|8443)$ ]]; then HAS_WEB="True"; fi
        if [[ "$v" != "Unknown" ]]; then SOFTWARE_DETECTED="$s"; VERSION_DETECTED="$v"; fi
    done
else
    printf "${CYAN}|${NC} %-6s ${CYAN}|${NC} %-8s ${CYAN}|${NC} %-20s ${CYAN}|${NC} %-40s ${CYAN}|${NC}\n" "-" "CLOSED" "None" "Target Unreachable"
fi
echo -e "${CYAN}+--------+----------+----------------------+------------------------------------------+${NC}"

# --- [PHASE 3] DEEP CONTEXT ---
echo -e "\n${YELLOW}[+] Phase 3: Deep Context & Forensics${NC}"
> "$WEB_HEADERS"
> "$TECH_STACK_FILE"

if [[ "$OS_NMAP" != "Unknown" ]]; then echo "OS Detection|$OS_NMAP" >> "$TECH_STACK_FILE"; fi

for entry in "${DETECTED_SERVICES[@]}"; do
    PORT=$(echo "$entry" | cut -d'|' -f1)
    SVC=$(echo "$entry" | cut -d'|' -f2)
    if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then continue; fi
    
    # Check for Web Services
    if [[ "$SCAN_STATUS" == "Active" ]] && { [[ "$SVC" =~ http ]] || [[ "$SVC" =~ ssl ]] || [[ "$SVC" =~ awselb ]] || [[ "$PORT" =~ ^(80|443|8080|8443)$ ]]; }; then
        PROTO="http"
        [[ "$SVC" == "https" || "$PORT" =~ ^(443|8443)$ ]] && PROTO="https"
        
        echo -e "    -> Probing $PROTO://$TARGET:$PORT..."
        if curl -v -sL -k -m 3 -I "$PROTO://$TARGET:$PORT" 2>&1 | grep -E "^< (HTTP|Server|Location)" > "$WEB_HEADERS" || true; then
             if [[ -s "$WEB_HEADERS" ]]; then
                 cat "$WEB_HEADERS" | sed 's/^/        /g'
                 SERVER_H=$(grep -i "^< Server:" "$WEB_HEADERS" | cut -d' ' -f3- | tr -d '\r' || echo "Unknown")
                 if [[ "$SERVER_H" != "Unknown" ]]; then echo "Web Server|$SERVER_H" >> "$TECH_STACK_FILE"; fi
                 if [[ -n "$SERVER_H" && "${OS_HEADER:-Unknown}" == "Unknown" ]]; then OS_HEADER="$SERVER_H"; fi
             fi
        fi
        
        if [[ "$PROTO" == "https" ]]; then
            CIPHERS_RAW=$(echo | timeout 3 openssl s_client -cipher 'RC4:3DES:DES:MD5' -connect "$TARGET:$PORT" 2>&1 || echo "")
            if echo "$CIPHERS_RAW" | grep -q "Cipher is"; then
                REMEDIATION_PLAN="${REMEDIATION_PLAN}|High|Weak Ciphers Detected|Disable RC4/3DES/CBC\n"
            else
                CIPHER_SUITES="Modern (AES-GCM)"
            fi
        fi
    fi

    # Check for Exposed Admin Services
    if [[ "$PORT" == "3389" ]]; then
        REMEDIATION_PLAN="${REMEDIATION_PLAN}|CRITICAL|Exposed RDP|Restrict Port 3389 Access Immediately\n"
        echo "Exposed Service|RDP (Remote Desktop)" >> "$TECH_STACK_FILE"
    fi
    if [[ "$PORT" == "3306" ]]; then
        REMEDIATION_PLAN="${REMEDIATION_PLAN}|High|Exposed MySQL|Bind MySQL to Localhost (127.0.0.1)\n"
        echo "Exposed Service|MySQL Database" >> "$TECH_STACK_FILE"
    fi
done

echo -e "${BOLD}TABLE: technology_stack${NC}"
echo -e "${CYAN}+----------------------+--------------------------------------------------+${NC}"
printf "${CYAN}|${NC} %-20s ${CYAN}|${NC} %-48s ${CYAN}|${NC}\n" "COMPONENT" "DETECTED VERSION / TYPE"
echo -e "${CYAN}+----------------------+--------------------------------------------------+${NC}"
if [[ -s "$TECH_STACK_FILE" ]]; then
    sort -u "$TECH_STACK_FILE" | while read -r line; do
        COMP=$(echo "$line" | cut -d'|' -f1)
        VAL=$(echo "$line" | cut -d'|' -f2)
        printf "${CYAN}|${NC} %-20s ${CYAN}|${NC} %-48s ${CYAN}|${NC}\n" "$COMP" "${VAL:0:48}"
    done
else
    printf "${CYAN}|${NC} %-20s ${CYAN}|${NC} %-48s ${CYAN}|${NC}\n" "Unknown" "No Web Technology Detected"
fi
echo -e "${CYAN}+----------------------+--------------------------------------------------+${NC}"

# --- [PHASE 4] NUCLEI SCANNING ---
if [[ "$HAS_NUCLEI" == "true" ]]; then
    echo -e "\n${YELLOW}[+] Phase 4: Targeted Vulnerability Scanning (Nuclei)${NC}"
    
    # Dynamic Protocol Selection
    NUCLEI_TARGET=""
    if [[ "$HAS_WEB" == "True" ]]; then
        # Check if port 443 is in the open ports list
        if echo "${DETECTED_SERVICES[@]}" | grep -q "443|"; then
            NUCLEI_TARGET="https://$TARGET"
        elif echo "${DETECTED_SERVICES[@]}" | grep -q "80|"; then
            NUCLEI_TARGET="http://$TARGET"
        else
            NUCLEI_TARGET="$TARGET"
        fi
        
        echo -e "    -> Executing Nuclei against: ${BOLD}$NUCLEI_TARGET${NC}"
        # Expanded Scope: CVEs, Misconfigs, Exposures, Default Logins
        "$NUCLEI_BIN" -u "$NUCLEI_TARGET" -tags cve,misconfig,exposure,vulnerability,default-login -severity critical,high,medium -json > "$NUCLEI_LOG" 2>&1 || echo "Nuclei Finished/Skipped"
        
        if [[ -s "$NUCLEI_LOG" ]]; then
            NUCLEI_HITS=$(grep "^{" "$NUCLEI_LOG" | jq -r '.info.id' | tr '\n' ' ' || echo "")
            if [[ -n "$NUCLEI_HITS" ]]; then
                echo -e "${BOLD}TABLE: nuclei_confirmed_hits${NC}"
                echo -e "${CYAN}+---------------------------+------------------------------------------+${NC}"
                grep "^{" "$NUCLEI_LOG" | jq -c '.' | while read -r line; do
                    ID=$(echo "$line" | jq -r '.info.id')
                    SEV=$(echo "$line" | jq -r '.info.severity')
                    printf "${CYAN}|${NC} ${RED}%-25s${NC} ${CYAN}|${NC} %-40s ${CYAN}|${NC}\n" "$ID" "$SEV"
                    REMEDIATION_PLAN="${REMEDIATION_PLAN}|Critical|Nuclei: $ID|Patch immediately ($SEV)\n"
                done
                echo -e "${CYAN}+---------------------------+------------------------------------------+${NC}"
            else
                echo -e "    -> ${GREEN}Nuclei found no critical/high/medium vulnerabilities.${NC}"
                NUCLEI_HITS="Clean"
            fi
        else
            echo -e "    -> ${GREY}No Nuclei results generated.${NC}"
            NUCLEI_HITS="Clean"
        fi
    else
        echo -e "    -> ${GREY}No Web Services detected. Skipping Nuclei Web Scan.${NC}"
        NUCLEI_HITS="Skipped (No Web)"
    fi
else
    NUCLEI_HITS="Skipped"
fi

# --- [PHASE 5] AI DISPARITY ANALYSIS (RECURSIVE LOOP WITH ERROR HANDLING) ---
echo -e "\n${YELLOW}[+] Phase 5: AI Disparity Analysis & Re-Check (The Autonomous Loop)${NC}"

CONTEXT="Ports detected: "
for entry in "${DETECTED_SERVICES[@]}"; do CONTEXT+="$entry, "; done

# Loop Init
LOOP_COUNT=0
AI_DISPARITY_LOG="Initial Scan Complete."
LAST_ERROR_FEEDBACK=""
PREVIOUS_CMD=""

while [ $LOOP_COUNT -lt $MAX_RECURSION_LOOPS ]; do
    LOOP_COUNT=$((LOOP_COUNT+1))
    echo -e "    -> ${CYAN}[Recursion $LOOP_COUNT/$MAX_RECURSION_LOOPS] Analyzing data with OpenAI...${NC}"

    # Feed the LAST ERROR into the prompt if it exists
    PROMPT_DISPARITY="You are the Sentinel Core Logic Engine.
    DATA:
    - Target: $TARGET
    - Current Ports: $CONTEXT
    - Nuclei Hits: $NUCLEI_HITS
    - Last Verification Output: $AI_DISPARITY_LOG
    
    SYSTEM FEEDBACK FROM PREVIOUS ATTEMPT: $LAST_ERROR_FEEDBACK
    
    TASK: Do we need another specific scan to confirm a suspicion?
    OUTPUT: Provide ONE raw command line to run, or output 'DONE' if sufficient info exists.
    CONSTRAINT: If proposing nmap, ALWAYS use '-Pn'. Do NOT repeat commands that just failed."

    ask_openai_persist "You are an automated Red Team Logic Engine." "$PROMPT_DISPARITY"
    AI_CMD_RAW=$(cat "$AI_RESPONSE_FILE")
    AI_CMD_CLEAN=$(echo "$AI_CMD_RAW" | grep -E "^(nmap|nuclei|curl)" | head -n 1 || echo "DONE")

    # Prevent Repeating the Exact Same Command
    if [[ "$AI_CMD_CLEAN" == "$PREVIOUS_CMD" ]] && [[ "$AI_CMD_CLEAN" != "DONE" ]]; then
        echo -e "    -> ${RED}[!] Loop Detected: AI suggested the same command again. Stopping recursion.${NC}"
        break
    fi
    PREVIOUS_CMD="$AI_CMD_CLEAN"

    if [[ "$AI_CMD_CLEAN" == "DONE" ]] || [[ -z "$AI_CMD_CLEAN" ]]; then
        echo -e "    -> ${GREEN}AI is satisfied with current data. Stopping recursion.${NC}"
        break
    else
        # Force -Pn
        if [[ "$AI_CMD_CLEAN" =~ ^nmap ]] && [[ "$AI_CMD_CLEAN" != *"-Pn"* ]]; then
             AI_CMD_CLEAN="${AI_CMD_CLEAN/nmap /nmap -Pn }"
        fi
        
        echo -e "    -> ${CYAN}AI Requesting deeper check:${NC} $AI_CMD_CLEAN"
        
        # Security Block
        if [[ "$AI_CMD_CLEAN" =~ rm\ |mv\ |dd\ |mkfs ]]; then
            echo -e "       ${RED}[!] Security Block: AI attempted dangerous command.${NC}"
            break
        fi

        # Execute with Error Capture
        OUTPUT_FULL=$(eval "$AI_CMD_CLEAN" 2>&1)
        EXIT_CODE=$?
        
        if [ $EXIT_CODE -eq 0 ]; then
             NEW_DATA=$(echo "$OUTPUT_FULL" | head -n 10)
             AI_DISPARITY_LOG="$AI_DISPARITY_LOG | Loop $LOOP_COUNT Result: $NEW_DATA"
             LAST_ERROR_FEEDBACK="Previous command SUCCESS."
             echo "$NEW_DATA" | sed 's/^/       /g'
        else
             echo -e "       ${RED}[!] Command Failed. Feeding error back to AI.${NC}"
             LAST_ERROR_FEEDBACK="Previous command FAILED with error: $OUTPUT_FULL"
        fi
    fi
done

# --- [PHASE 6] CVE VALIDATION (FULL LIST - POST RECURSION) ---
echo -e "\n${YELLOW}[+] Phase 6: CVE Validation (Nmap & Correlation)${NC}"
echo -e "${BOLD}TABLE: vulnerability_validation${NC}"
echo -e "${CYAN}+---------------------+----------------------+----------------------+-------------------------------------------+${NC}"
printf "${CYAN}|${NC} %-19s ${CYAN}|${NC} %-20s ${CYAN}|${NC} %-20s ${CYAN}|${NC} %-41s ${CYAN}|${NC}\n" "CVE ID" "STATUS" "CONTEXT / SOURCE" "VALIDATION COMMAND"
echo -e "${CYAN}+---------------------+----------------------+----------------------+-------------------------------------------+${NC}"

if [[ "$CVES_COUNT" -gt 0 ]]; then
    echo -e "    -> Checking ALL known CVEs against exposed services..."
    
    # Use dynamically found ports from Phase 2/5 for accurate checking
    # Fallback to standard ports if parsing failed
    CHECK_PORTS="${OPEN_PORTS_COMMA:-80,443}"
    
    # Capture output to file to parse specific confirmed hits
    nmap -Pn -sV -p "$CHECK_PORTS" --script vulners "$TARGET" > "$CVE_SCAN_OUT" 2>/dev/null || true
    
    # Iterate through ALL CVEs
    for cve in $CVES_LIST; do
        STATUS="${YELLOW}Potential${NC}"
        CONTEXT="Shodan Passive"
        
        # Check if Nmap confirmed it
        if grep -q "$cve" "$CVE_SCAN_OUT"; then
            STATUS="${RED}CONFIRMED${NC}"
            CONTEXT="Nmap Script Match"
        fi
        
        CMD="nmap -Pn --script vulners $TARGET"
        printf "${CYAN}|${NC} %-19s ${CYAN}|${NC} %-29b ${CYAN}|${NC} %-20s ${CYAN}|${NC} %-41s ${CYAN}|${NC}\n" "$cve" "$STATUS" "$CONTEXT" "${CMD:0:41}"
    done
else
    printf "${CYAN}|${NC} %-19s ${CYAN}|${NC} %-20s ${CYAN}|${NC} %-20s ${CYAN}|${NC} %-41s ${CYAN}|${NC}\n" "None" "Clean" "-" "-"
fi
echo -e "${CYAN}+---------------------+----------------------+----------------------+-------------------------------------------+${NC}"

# --- [PHASE 7] SECOND AI OPINION ---
echo -e "\n${YELLOW}[+] Phase 7: Secondary AI Verification (Risk Assessment)${NC}"
PROMPT_SECOND="You are a Principal Security Architect.
Review the previous disparity findings: $AI_DISPARITY_LOG

TASK: Classify the findings into one of these categories:
1. 'CONFIRMED VULNERABILITY' (Exploitable CVEs or clear misconfigs)
2. 'ARCHITECTURAL RISK' (Exposed Admin Panels, SSH/RDP to internet, DBs on public IP)
3. 'FALSE POSITIVE' (Just standard open ports with no risk)

Output: Category Name followed by a brief technical explanation."

ask_openai_persist "You are a Principal Security Architect." "$PROMPT_SECOND"
AI_VERIFICATION_LOG=$(cat "$AI_RESPONSE_FILE")
echo -e "    -> ${CYAN}Analysis:${NC} $AI_VERIFICATION_LOG"

# --- [PHASE 8] REPORT ---
ISSUES_LIST=$(echo -e "$REMEDIATION_PLAN" | cut -d'|' -f3 | tr '\n' ', ' | sed 's/,$//')
if [[ -z "$ISSUES_LIST" ]]; then ISSUES_LIST="None detected."; fi

PROMPT_SUM="Analyze the following technical findings for target $TARGET.
CONTEXT:
- OS: ${OS_NMAP}
- Software: $SOFTWARE_DETECTED $VERSION_DETECTED
- Open Ports: $PORTS
- Confirmed Vulnerabilities (Nuclei): $NUCLEI_HITS
- Potential Vulnerabilities (Shodan): $SHODAN_CVES_CONTEXT
- Critical Exposures: $REMEDIATION_PLAN
- AI Risk Assessment: $AI_VERIFICATION_LOG

TASK: Output a strict 6-point technical assessment (Principal Security Architect Level):
1. WHAT: [Identify stack components, OS versions, and specific tech identifiers]
2. WHERE: [Map attack surface: Specific ports, API endpoints, or services exposed]
3. WHY: [Technical Root Cause Analysis. HIGHLIGHT EXPOSED ADMIN SERVICES (RDP/MySQL/SSH) AS CRITICAL ARCHITECTURAL FLAWS regardless of CVEs.]
4. WHY NOT: [Mitigating Controls identified (e.g., WAF, TCP wrapping, specific patch levels)]
5. HOW: [Precise Remediation. PROVIDE EXACT FIREWALL RULES for Linux (ufw/iptables) or Windows (PowerShell) to restrict admin ports.]
6. RISK: [Score: Low/Medium/High/Critical based on exploitability. If RDP/MySQL is public, score is HIGH/CRITICAL.]

CONSTRAINT:
- Use industry-standard terminology (e.g., 'Lateral Movement', 'RCE', 'Information Disclosure').
- Format each point as a single paragraph.
- Ensure lines do not exceed 76 characters in length (use hard wraps)."

echo -e "\n${YELLOW}[+] Phase 8: Final AI Report Generation${NC}"
echo -e "    -> Generating Executive Summary..."
ask_openai_persist "You are a Principal Security Architect." "$PROMPT_SUM"
AI_OUT=$(cat "$AI_RESPONSE_FILE")

echo -e "${BOLD}ADVISORY: autonomous_executive_summary${NC}"
echo -e "${CYAN}+--------------------------------------------------------------------------------+${NC}"
CLEAN_OUT=$(echo "$AI_OUT" | sed 's/```//g')
echo "$CLEAN_OUT" | fold -s -w 76 | while read -r line; do
    printf "${CYAN}|${NC} %-78s ${CYAN}|${NC}\n" "$line"
done
echo -e "${CYAN}+--------------------------------------------------------------------------------+${NC}"

# --- [PHASE 9] COST ACCOUNTING ---
COST_INPUT=$(awk "BEGIN {printf \"%.4f\", $OPENAI_INPUT_TOKENS * $PRICE_INPUT_1M / 1000000}")
COST_OUTPUT=$(awk "BEGIN {printf \"%.4f\", $OPENAI_OUTPUT_TOKENS * $PRICE_OUTPUT_1M / 1000000}")
TOTAL_COST=$(awk "BEGIN {printf \"%.4f\", $COST_INPUT + $COST_OUTPUT}")

echo -e "\n${BOLD}REPORT: session_accounting${NC}"
echo -e "${CYAN}+--------------------------+---------------------+-------------------+${NC}"
printf "${CYAN}|${NC} %-24s ${CYAN}|${NC} %-19s ${CYAN}|${NC} %-17s ${CYAN}|${NC}\n" "Shodan API" "$SHODAN_QUERIES Query" "Included"
printf "${CYAN}|${NC} %-24s ${CYAN}|${NC} %-19s ${CYAN}|${NC} $%-16s ${CYAN}|${NC}\n" "OpenAI Input ($AI_MODEL)" "$OPENAI_INPUT_TOKENS Tokens" "$COST_INPUT"
printf "${CYAN}|${NC} %-24s ${CYAN}|${NC} %-19s ${CYAN}|${NC} $%-16s ${CYAN}|${NC}\n" "OpenAI Output ($AI_MODEL)" "$OPENAI_OUTPUT_TOKENS Tokens" "$COST_OUTPUT"
echo -e "${CYAN}+--------------------------+---------------------+-------------------+${NC}"
printf "${CYAN}|${NC} %-45s ${CYAN}|${NC} ${GREEN}$%-16s${NC} ${CYAN}|${NC}\n" "TOTAL SESSION COST" "$TOTAL_COST"
echo -e "${CYAN}+------------------------------------------------+-------------------+${NC}"
echo ""
