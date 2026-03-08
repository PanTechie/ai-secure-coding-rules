# =============================================================================
#  🛡  AI Secure Coding Rules — Interactive Installer (PowerShell)
#  https://github.com/PanTechie/ai-secure-coding-rules
#
#  Run remotely (PowerShell 5+ / PowerShell Core):
#    & ([scriptblock]::Create((irm 'https://raw.githubusercontent.com/PanTechie/ai-secure-coding-rules/main/install.ps1')))
#
#  Run locally:
#    .\install.ps1
#
#  If blocked by execution policy, run first:
#    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
# =============================================================================
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$REPO_RAW  = 'https://raw.githubusercontent.com/PanTechie/ai-secure-coding-rules/main'
$REPO_URL  = 'https://github.com/PanTechie/ai-secure-coding-rules'

# ── Skill registry ────────────────────────────────────────────────────────────
# Each entry: [key, label, standards-filename]
$SKILLS = @(
  @{ Key = 'security-api';        Label = 'API Security (OWASP API Top 10:2023)';          Std = 'code-security-owasp-api-top10-2023.md' }
  @{ Key = 'security-asvs';       Label = 'OWASP ASVS 5.0';                                Std = 'code-security-owasp-asvs-5.0.md' }
  @{ Key = 'security-cwe';        Label = 'CWE Top 25:2025';                               Std = 'code-security-cwe-top25-2025.md' }
  @{ Key = 'security-iac';        Label = 'Infrastructure as Code (Docker / K8s / Terraform)'; Std = 'code-security-iac.md' }
  @{ Key = 'security-javascript'; Label = 'JavaScript / TypeScript / Node.js';             Std = 'code-security-javascript.md' }
  @{ Key = 'security-llm';        Label = 'LLM & AI Application Security';                 Std = 'code-security-owasp-llm-top10-2025.md' }
  @{ Key = 'security-mobile';     Label = 'Mobile Security (Android / iOS)';               Std = 'code-security-mobile.md' }
  @{ Key = 'security-php';        Label = 'PHP Security';                                  Std = 'code-security-php.md' }
  @{ Key = 'security-privacy';    Label = 'Privacy & Data Protection (GDPR / LGPD / CCPA)'; Std = 'code-security-privacy.md' }
  @{ Key = 'security-python3';    Label = 'Python 3 Security';                             Std = 'code-security-python3.md' }
  @{ Key = 'security-sbd';        Label = 'Secure by Design (CISA / NIST SSDF)';           Std = 'code-security-secure-by-design.md' }
  @{ Key = 'security-secrets';    Label = 'Secrets Management';                            Std = 'code-security-secrets.md' }
  @{ Key = 'security-web';        Label = 'Web Application Security (OWASP Top 10:2025)';  Std = 'code-security-owasp-top10-2025.md' }
  @{ Key = 'security-csharp';    Label = 'C# / .NET Security';                             Std = 'code-security-csharp.md' }
  @{ Key = 'security-jvm';       Label = 'Java & Kotlin (JVM) Security';                   Std = 'code-security-jvm.md' }
  @{ Key = 'security-clojure';   Label = 'Clojure Security';                               Std = 'code-security-clojure.md' }
  @{ Key = 'security-ruby';     Label = 'Ruby & Rails Security';                           Std = 'code-security-ruby.md' }
  @{ Key = 'security-elixir';  Label = 'Elixir & Phoenix Security';                       Std = 'code-security-elixir.md' }
  @{ Key = 'security-c-cpp';   Label = 'C / C++ Security';                                Std = 'code-security-c-cpp.md' }
  @{ Key = 'security-dart';   Label = 'Dart & Flutter Security';                          Std = 'code-security-dart.md' }
  @{ Key = 'security-objc';   Label = 'Objective-C Security';                             Std = 'code-security-objc.md' }
  @{ Key = 'security-swift';  Label = 'Swift Security';                                   Std = 'code-security-swift.md' }
  @{ Key = 'security-go';     Label = 'Go Security';                                      Std = 'code-security-go.md' }
)

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Banner {
  Write-Host ""
  Write-Host "  +--------------------------------------------------------------+" -ForegroundColor Cyan
  Write-Host "  |          🛡  AI Secure Coding Rules — Installer             |" -ForegroundColor Cyan
  Write-Host ("  |          {0,-52}|" -f $REPO_URL) -ForegroundColor Cyan
  Write-Host "  +--------------------------------------------------------------+" -ForegroundColor Cyan
  Write-Host ""
  Write-Host "  Drop-in security awareness for AI coding assistants."
  Write-Host "  security-essentials.md is always included by default." -ForegroundColor Yellow
  Write-Host ""
}

function Download-File {
  param([string]$Url, [string]$Dest)
  $dir = Split-Path $Dest -Parent
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  try {
    Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing -ErrorAction Stop | Out-Null
  } catch {
    Write-Host "  [FAIL] Could not download: $Url" -ForegroundColor Red
    throw
  }
}

function Install-ClaudeCode {
  param([string]$Target, [array]$Selected)
  Write-Host ""
  Write-Host "  -> Claude Code  (.claude/)" -ForegroundColor Cyan
  Download-File "$REPO_RAW/.claude/rules/security-essentials.md" `
                "$Target/.claude/rules/security-essentials.md"
  Write-Host "     [OK] rules/security-essentials.md" -ForegroundColor Green
  foreach ($s in $Selected) {
    Download-File "$REPO_RAW/.claude/skills/$($s.Key)/SKILL.md" `
                  "$Target/.claude/skills/$($s.Key)/SKILL.md"
    Download-File "$REPO_RAW/.claude/skills/$($s.Key)/rules.md" `
                  "$Target/.claude/skills/$($s.Key)/rules.md"
    Write-Host "     [OK] skills/$($s.Key)/" -ForegroundColor Green
  }
}

function Install-GeminiAgent {
  param([string]$Target, [array]$Selected)
  Write-Host ""
  Write-Host "  -> Gemini Antigravity  (.agent/)" -ForegroundColor Cyan
  Download-File "$REPO_RAW/.agent/rules/security-essentials.md" `
                "$Target/.agent/rules/security-essentials.md"
  Write-Host "     [OK] rules/security-essentials.md" -ForegroundColor Green
  foreach ($s in $Selected) {
    Download-File "$REPO_RAW/.agent/skills/$($s.Key)/SKILL.md" `
                  "$Target/.agent/skills/$($s.Key)/SKILL.md"
    Download-File "$REPO_RAW/.agent/skills/$($s.Key)/rules.md" `
                  "$Target/.agent/skills/$($s.Key)/rules.md"
    Write-Host "     [OK] skills/$($s.Key)/" -ForegroundColor Green
  }
}

function Install-Cursor {
  param([string]$Target, [array]$Selected)
  Write-Host ""
  Write-Host "  -> Cursor  (.cursor/)" -ForegroundColor Cyan
  Write-Host "     Note: All Cursor rules are always-on (.mdc)" -ForegroundColor DarkGray
  Download-File "$REPO_RAW/.cursor/rules/security-essentials.mdc" `
                "$Target/.cursor/rules/security-essentials.mdc"
  Write-Host "     [OK] rules/security-essentials.mdc" -ForegroundColor Green
  foreach ($s in $Selected) {
    $stdFile = $s.Std
    $mdc     = $stdFile -replace '\.md$', '.mdc'
    $dest    = "$Target/.cursor/rules/$mdc"
    $tmpFile = [System.IO.Path]::GetTempFileName()
    try {
      Invoke-WebRequest -Uri "$REPO_RAW/standards/$stdFile" -OutFile $tmpFile -UseBasicParsing | Out-Null
      $dir = Split-Path $dest -Parent
      if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
      $frontmatter = "---`nalwaysApply: true`n---`n"
      $content = [System.IO.File]::ReadAllText($tmpFile)
      [System.IO.File]::WriteAllText($dest, $frontmatter + $content)
      Write-Host "     [OK] rules/$mdc" -ForegroundColor Green
    } finally {
      Remove-Item $tmpFile -ErrorAction SilentlyContinue
    }
  }
}

function Install-OpenAICodex {
  param([string]$Target)
  Write-Host ""
  Write-Host "  -> OpenAI Codex  (AGENTS.md)" -ForegroundColor Cyan
  Write-Host "     Note: Single file; essentials only (32 KB limit)" -ForegroundColor DarkGray
  Download-File "$REPO_RAW/AGENTS.md" "$Target/AGENTS.md"
  Write-Host "     [OK] AGENTS.md" -ForegroundColor Green
}

# ── Main interactive flow ─────────────────────────────────────────────────────
function Main {
  Write-Banner

  # 1. Target directory
  Write-Host "Install to directory (Enter = current directory):" -ForegroundColor White
  $rawDir = Read-Host "  >"
  if ([string]::IsNullOrWhiteSpace($rawDir)) {
    $targetDir = (Get-Location).Path
  } else {
    $targetDir = $rawDir.Trim()
  }
  Write-Host ""

  # 2. Platform selection
  Write-Host "Platforms to install:" -ForegroundColor White
  Write-Host "  [1] Claude Code        (.claude/)"
  Write-Host "  [2] Gemini Antigravity (.agent/)"
  Write-Host "  [3] Cursor             (.cursor/)"
  Write-Host "  [4] OpenAI Codex       (AGENTS.md)"
  Write-Host "  [5] All platforms"
  Write-Host ""
  $rawPlat = Read-Host "  Enter numbers separated by commas (e.g. 1,3)"
  Write-Host ""

  $doClaude = $false; $doAgent = $false; $doCursor = $false; $doCodex = $false
  foreach ($p in ($rawPlat -split ',')) {
    switch ($p.Trim()) {
      '1' { $doClaude = $true }
      '2' { $doAgent  = $true }
      '3' { $doCursor = $true }
      '4' { $doCodex  = $true }
      '5' { $doClaude = $true; $doAgent = $true; $doCursor = $true; $doCodex = $true }
    }
  }

  if (-not ($doClaude -or $doAgent -or $doCursor -or $doCodex)) {
    Write-Host "No platform selected. Aborting." -ForegroundColor Red
    return
  }

  # 3. Skill selection
  Write-Host "Skills to install: (security-essentials always included)" -ForegroundColor White
  for ($i = 0; $i -lt $SKILLS.Count; $i++) {
    Write-Host ("  [{0,2}] {1}" -f ($i + 1), $SKILLS[$i].Label)
  }
  Write-Host "  [ a] All skills"
  Write-Host "  [ n] None (essentials only)"
  Write-Host ""
  $rawSkills = Read-Host "  Enter numbers separated by commas, [a]ll, or [n]one"
  Write-Host ""

  $selected = @()
  $rawSkills = $rawSkills.Trim()

  if ($rawSkills -match '^[Aa]') {
    $selected = $SKILLS
  } elseif ($rawSkills -match '^[Nn]') {
    $selected = @()
  } else {
    foreach ($n in ($rawSkills -split ',')) {
      $n = $n.Trim()
      if ($n -match '^\d+$') {
        $idx = [int]$n - 1
        if ($idx -ge 0 -and $idx -lt $SKILLS.Count) {
          $selected += $SKILLS[$idx]
        }
      }
    }
  }

  # 4. Summary + confirmation
  Write-Host "Ready to install:" -ForegroundColor White
  Write-Host ""
  if ($doClaude) { Write-Host "  [OK] Claude Code"        -ForegroundColor Green }
  if ($doAgent)  { Write-Host "  [OK] Gemini Antigravity" -ForegroundColor Green }
  if ($doCursor) { Write-Host "  [OK] Cursor"             -ForegroundColor Green }
  if ($doCodex)  { Write-Host "  [OK] OpenAI Codex"       -ForegroundColor Green }
  Write-Host ""
  Write-Host "  Always included:  security-essentials"
  if ($selected.Count -gt 0) {
    Write-Host "  Skills:"
    foreach ($s in $selected) { Write-Host "    * $($s.Label)" -ForegroundColor DarkGray }
  } else {
    Write-Host "  Skills: none"
  }
  Write-Host ""
  Write-Host "  Destination: $targetDir" -ForegroundColor Cyan
  Write-Host ""
  $confirm = Read-Host "Proceed? [Y/n]"
  if ($confirm -match '^[Nn]') {
    Write-Host "Aborted."
    return
  }

  # 5. Install
  Write-Host ""
  Write-Host "Downloading..." -ForegroundColor White

  if ($doClaude) { Install-ClaudeCode  -Target $targetDir -Selected $selected }
  if ($doAgent)  { Install-GeminiAgent -Target $targetDir -Selected $selected }
  if ($doCursor) { Install-Cursor      -Target $targetDir -Selected $selected }
  if ($doCodex)  { Install-OpenAICodex -Target $targetDir }

  # 6. Done
  Write-Host ""
  Write-Host "Done! " -ForegroundColor Green -NoNewline
  Write-Host "Security rules installed to " -NoNewline
  Write-Host $targetDir -ForegroundColor Cyan
  Write-Host ""
  Write-Host "  Commit the rules to your repository:"
  Write-Host "  git add .claude/ .agent/ .cursor/ AGENTS.md" -ForegroundColor DarkGray
  Write-Host "  git commit -m 'chore: add AI secure coding rules'" -ForegroundColor DarkGray
  Write-Host ""
}

Main
