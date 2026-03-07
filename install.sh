#!/usr/bin/env bash
# =============================================================================
#  🛡  AI Secure Coding Rules — Interactive Installer
#  https://github.com/PanTechie/ai-secure-coding-rules
#
#  Run remotely:
#    bash <(curl -fsSL https://raw.githubusercontent.com/PanTechie/ai-secure-coding-rules/main/install.sh)
#
#  Run locally:
#    bash install.sh
# =============================================================================
set -eo pipefail

REPO_RAW="https://raw.githubusercontent.com/PanTechie/ai-secure-coding-rules/main"
REPO_URL="https://github.com/PanTechie/ai-secure-coding-rules"

# ── Colors (only when stdout is a terminal) ───────────────────────────────────
if [ -t 1 ]; then
  RED='\033[0;31m'   GREEN='\033[0;32m'  YELLOW='\033[1;33m'
  BLUE='\033[0;34m'  CYAN='\033[0;36m'   BOLD='\033[1m'
  DIM='\033[2m'      RESET='\033[0m'
else
  RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' DIM='' RESET=''
fi

# ── Guard: must run interactively (not piped) ─────────────────────────────────
if [ ! -t 0 ]; then
  echo ""
  echo "This installer requires interactive input."
  echo "Please run it as:"
  echo ""
  echo "  bash <(curl -fsSL ${REPO_RAW}/install.sh)"
  echo ""
  exit 1
fi

# ── Skill registry ────────────────────────────────────────────────────────────
# Format: "skill-key|Label|standards-filename"
SKILLS=(
  "security-api|API Security (OWASP API Top 10:2023)|code-security-owasp-api-top10-2023.md"
  "security-asvs|OWASP ASVS 5.0|code-security-owasp-asvs-5.0.md"
  "security-cwe|CWE Top 25:2025|code-security-cwe-top25-2025.md"
  "security-iac|Infrastructure as Code (Docker / K8s / Terraform)|code-security-iac.md"
  "security-javascript|JavaScript / TypeScript / Node.js|code-security-javascript.md"
  "security-llm|LLM & AI Application Security|code-security-owasp-llm-top10-2025.md"
  "security-mobile|Mobile Security (Android / iOS)|code-security-mobile.md"
  "security-php|PHP Security|code-security-php.md"
  "security-privacy|Privacy & Data Protection (GDPR / LGPD / CCPA)|code-security-privacy.md"
  "security-python3|Python 3 Security|code-security-python3.md"
  "security-sbd|Secure by Design (CISA / NIST SSDF)|code-security-secure-by-design.md"
  "security-secrets|Secrets Management|code-security-secrets.md"
  "security-web|Web Application Security (OWASP Top 10:2025)|code-security-owasp-top10-2025.md"
  "security-csharp|C# / .NET Security|code-security-csharp.md"
  "security-jvm|Java & Kotlin (JVM) Security|code-security-jvm.md"
  "security-clojure|Clojure Security|code-security-clojure.md"
  "security-ruby|Ruby & Rails Security|code-security-ruby.md"
  "security-elixir|Elixir & Phoenix Security|code-security-elixir.md"
)

# ── Helpers ───────────────────────────────────────────────────────────────────
banner() {
  echo ""
  echo -e "${CYAN}${BOLD}  ┌──────────────────────────────────────────────────────────────┐"
  echo    "  │          🛡  AI Secure Coding Rules — Installer             │"
  printf  "  │          %-52s│\n" "$REPO_URL"
  echo -e "  └──────────────────────────────────────────────────────────────┘${RESET}"
  echo ""
  echo -e "  Drop-in security awareness for AI coding assistants."
  echo -e "  ${YELLOW}security-essentials.md is always included by default.${RESET}"
  echo ""
}

download_file() {
  local url="$1" dest="$2"
  mkdir -p "$(dirname "$dest")"
  if ! curl -fsSL "$url" -o "$dest" 2>/dev/null; then
    echo -e "  ${RED}✗ Failed to download: $url${RESET}" >&2
    return 1
  fi
}

skill_key()       { echo "$1" | cut -d'|' -f1; }
skill_label()     { echo "$1" | cut -d'|' -f2; }
skill_stdfile()   { echo "$1" | cut -d'|' -f3; }

# ── Platform installers ───────────────────────────────────────────────────────
install_claude() {
  local target="$1"; shift
  echo -e "\n  ${BLUE}${BOLD}→ Claude Code  (.claude/)${RESET}"
  download_file "$REPO_RAW/.claude/rules/security-essentials.md" \
    "$target/.claude/rules/security-essentials.md"
  echo -e "    ${GREEN}✓${RESET} rules/security-essentials.md"
  for entry in "$@"; do
    local key; key=$(skill_key "$entry")
    download_file "$REPO_RAW/.claude/skills/$key/SKILL.md" \
      "$target/.claude/skills/$key/SKILL.md"
    download_file "$REPO_RAW/.claude/skills/$key/rules.md" \
      "$target/.claude/skills/$key/rules.md"
    echo -e "    ${GREEN}✓${RESET} skills/$key/"
  done
}

install_agent() {
  local target="$1"; shift
  echo -e "\n  ${BLUE}${BOLD}→ Gemini Antigravity  (.agent/)${RESET}"
  download_file "$REPO_RAW/.agent/rules/security-essentials.md" \
    "$target/.agent/rules/security-essentials.md"
  echo -e "    ${GREEN}✓${RESET} rules/security-essentials.md"
  for entry in "$@"; do
    local key; key=$(skill_key "$entry")
    download_file "$REPO_RAW/.agent/skills/$key/SKILL.md" \
      "$target/.agent/skills/$key/SKILL.md"
    download_file "$REPO_RAW/.agent/skills/$key/rules.md" \
      "$target/.agent/skills/$key/rules.md"
    echo -e "    ${GREEN}✓${RESET} skills/$key/"
  done
}

install_cursor() {
  local target="$1"; shift
  echo -e "\n  ${BLUE}${BOLD}→ Cursor  (.cursor/)${RESET}"
  echo -e "  ${DIM}  All Cursor rules are always-on (.mdc)${RESET}"
  download_file "$REPO_RAW/.cursor/rules/security-essentials.mdc" \
    "$target/.cursor/rules/security-essentials.mdc"
  echo -e "    ${GREEN}✓${RESET} rules/security-essentials.mdc"
  for entry in "$@"; do
    local key stdfile dest tmpfile
    key=$(skill_key "$entry")
    stdfile=$(skill_stdfile "$entry")
    dest="$target/.cursor/rules/${stdfile%.md}.mdc"
    tmpfile=$(mktemp)
    curl -fsSL "$REPO_RAW/standards/$stdfile" -o "$tmpfile" 2>/dev/null
    { printf -- '---\nalwaysApply: true\n---\n'; cat "$tmpfile"; } > "$dest"
    rm -f "$tmpfile"
    echo -e "    ${GREEN}✓${RESET} rules/${stdfile%.md}.mdc"
  done
}

install_codex() {
  local target="$1"
  echo -e "\n  ${BLUE}${BOLD}→ OpenAI Codex  (AGENTS.md)${RESET}"
  echo -e "  ${DIM}  Single file; essentials only (32 KB limit)${RESET}"
  download_file "$REPO_RAW/AGENTS.md" "$target/AGENTS.md"
  echo -e "    ${GREEN}✓${RESET} AGENTS.md"
}

# ── Main interactive flow ─────────────────────────────────────────────────────
main() {
  banner

  # 1. Target directory
  echo -e "${BOLD}Install to directory${RESET} ${DIM}(Enter = current directory)${RESET}:"
  read -rp "  > " TARGET_DIR
  TARGET_DIR="${TARGET_DIR:-$(pwd)}"
  TARGET_DIR="${TARGET_DIR/#\~/$HOME}"
  echo ""

  # 2. Platform selection
  echo -e "${BOLD}Platforms to install:${RESET}"
  echo "  [1] Claude Code        (.claude/)"
  echo "  [2] Gemini Antigravity (.agent/)"
  echo "  [3] Cursor             (.cursor/)"
  echo "  [4] OpenAI Codex       (AGENTS.md)"
  echo "  [5] All platforms"
  echo ""
  read -rp "  Enter numbers separated by commas (e.g. 1,3): " RAW_PLATFORMS
  echo ""

  DO_CLAUDE=false; DO_AGENT=false; DO_CURSOR=false; DO_CODEX=false
  IFS=',' read -ra _plat_choices <<< "${RAW_PLATFORMS// /}"
  for p in "${_plat_choices[@]}"; do
    case "$p" in
      1) DO_CLAUDE=true ;;
      2) DO_AGENT=true  ;;
      3) DO_CURSOR=true ;;
      4) DO_CODEX=true  ;;
      5) DO_CLAUDE=true; DO_AGENT=true; DO_CURSOR=true; DO_CODEX=true ;;
    esac
  done

  if ! $DO_CLAUDE && ! $DO_AGENT && ! $DO_CURSOR && ! $DO_CODEX; then
    echo -e "${RED}No platform selected. Aborting.${RESET}"
    exit 1
  fi

  # 3. Skill selection
  echo -e "${BOLD}Skills to install:${RESET} ${DIM}(security-essentials always included)${RESET}"
  for i in "${!SKILLS[@]}"; do
    printf "  [%2d] %s\n" "$((i + 1))" "$(skill_label "${SKILLS[$i]}")"
  done
  echo "  [ a] All skills"
  echo "  [ n] None (essentials only)"
  echo ""
  read -rp "  Enter numbers separated by commas, [a]ll, or [n]one: " RAW_SKILLS
  echo ""

  SELECTED=()
  RAW_SKILLS="${RAW_SKILLS// /}"
  if   [[ "$RAW_SKILLS" =~ ^[Aa] ]]; then
    SELECTED=("${SKILLS[@]}")
  elif [[ "$RAW_SKILLS" =~ ^[Nn] ]]; then
    SELECTED=()
  else
    IFS=',' read -ra _nums <<< "$RAW_SKILLS"
    for n in "${_nums[@]}"; do
      if [[ "$n" =~ ^[0-9]+$ ]]; then
        local idx=$(( n - 1 ))
        if (( idx >= 0 && idx < ${#SKILLS[@]} )); then
          SELECTED+=("${SKILLS[$idx]}")
        fi
      fi
    done
  fi

  # 4. Summary + confirmation
  echo -e "${BOLD}Ready to install:${RESET}"
  echo ""
  $DO_CLAUDE && echo -e "  ${GREEN}✓${RESET} Claude Code"
  $DO_AGENT  && echo -e "  ${GREEN}✓${RESET} Gemini Antigravity"
  $DO_CURSOR && echo -e "  ${GREEN}✓${RESET} Cursor"
  $DO_CODEX  && echo -e "  ${GREEN}✓${RESET} OpenAI Codex"
  echo ""
  echo    "  Always included:  security-essentials"
  if (( ${#SELECTED[@]} > 0 )); then
    echo "  Skills:"
    for entry in "${SELECTED[@]}"; do
      echo -e "    ${DIM}•${RESET} $(skill_label "$entry")"
    done
  else
    echo "  Skills: none"
  fi
  echo ""
  echo -e "  Destination: ${CYAN}${TARGET_DIR}${RESET}"
  echo ""
  read -rp "Proceed? [Y/n]: " CONFIRM
  CONFIRM="${CONFIRM:-Y}"
  if [[ "$CONFIRM" =~ ^[Nn] ]]; then
    echo "Aborted."
    exit 0
  fi

  # 5. Install
  echo ""
  echo -e "${BOLD}Downloading...${RESET}"

  if $DO_CLAUDE; then
    if (( ${#SELECTED[@]} > 0 )); then
      install_claude "$TARGET_DIR" "${SELECTED[@]}"
    else
      install_claude "$TARGET_DIR"
    fi
  fi

  if $DO_AGENT; then
    if (( ${#SELECTED[@]} > 0 )); then
      install_agent "$TARGET_DIR" "${SELECTED[@]}"
    else
      install_agent "$TARGET_DIR"
    fi
  fi

  if $DO_CURSOR; then
    if (( ${#SELECTED[@]} > 0 )); then
      install_cursor "$TARGET_DIR" "${SELECTED[@]}"
    else
      install_cursor "$TARGET_DIR"
    fi
  fi

  $DO_CODEX && install_codex "$TARGET_DIR"

  # 6. Done
  echo ""
  echo -e "${GREEN}${BOLD}Done!${RESET} Security rules installed to ${CYAN}${TARGET_DIR}${RESET}"
  echo ""
  echo -e "  Commit the rules to your repository:"
  echo -e "  ${DIM}git add .claude/ .agent/ .cursor/ AGENTS.md${RESET}"
  echo -e "  ${DIM}git commit -m 'chore: add AI secure coding rules'${RESET}"
  echo ""
}

main
