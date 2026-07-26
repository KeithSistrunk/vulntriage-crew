<#
.SYNOPSIS
    Unattended crew run. Start it and walk away.

.DESCRIPTION
    Wraps `main.py` with everything an unattended run needs and nothing it does not:

      - uses .venv\Scripts\python.exe, never whatever `python` resolves to
        (the tests pass under the system interpreter because pydantic is installed
        globally; crewai only exists in the venv, so a green test suite is no
        guarantee the crew will start)
      - restarts Ollama if it has died, and waits until it actually answers
      - keeps the Arc iGPU enabled (OLLAMA_IGPU_ENABLE=1), which Ollama otherwise
        drops, silently falling back to CPU
      - blocks every interactive path: stdin is EOF, CrewAI tracing and telemetry
        are off. Nothing can sit waiting for a keystroke that will never come
      - timestamped log per run under logs\
      - file locks never lose a run: main.py writes beside a locked file instead

    Exit codes:
      0  ran, guard clean            3  ran, narrative guard flagged a claim (-Strict)
      2  LLM backend unavailable     4  Ollama could not be revived
      1  findings file missing       other: propagated from main.py

.EXAMPLE
    .\scripts\lab_run.ps1
    .\scripts\lab_run.ps1 -Strict
    .\scripts\lab_run.ps1 -Model llama3.1:8b -TopN 8 -OutputDir output-lab
    .\scripts\lab_run.ps1 -FindingsPath data\sample_findings.csv -FallbackOffline
    .\scripts\lab_run.ps1 -StreamAgents     # stream each agent's reasoning into the log
#>
[CmdletBinding()]
param(
    # Not -Input: $Input is a reserved automatic variable in PowerShell.
    [string]$FindingsPath,
    [string]$OutputDir,
    [string]$Model,
    [int]$TopN,
    [switch]$Strict,
    # Not -Verbose: CmdletBinding already claims that for Write-Verbose.
    [switch]$StreamAgents,
    # Off by default on purpose: a run that quietly became an offline run looks
    # like a successful crew run with an empty narrative. Opt in if you would
    # rather have the deterministic report than nothing.
    [switch]$FallbackOffline,
    [int]$OllamaTimeoutSeconds = 90,
    [string[]]$ExtraArgs
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $ProjectRoot '.venv\Scripts\python.exe'
$OllamaApp = Join-Path $env:LOCALAPPDATA 'Programs\Ollama\ollama app.exe'
$OllamaUrl = 'http://127.0.0.1:11434'

$LogDir = Join-Path $ProjectRoot 'logs'
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$LogFile = Join-Path $LogDir "lab_run-$Stamp.log"

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'HH:mm:ss'), $Level, $Message
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -Encoding utf8
}

function Test-Ollama {
    try {
        $r = Invoke-RestMethod -Uri "$OllamaUrl/api/version" -TimeoutSec 4
        return $r.version
    } catch { return $null }
}

function Start-OllamaIfDead {
    $version = Test-Ollama
    if ($version) {
        Write-Log "Ollama already up (v$version)."
        return $true
    }

    Write-Log 'Ollama is not answering. Restarting it.' 'WARN'
    # Clear any half-dead processes first, or the new one binds nothing.
    Get-Process -Name 'ollama', 'ollama app' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    if (Test-Path $OllamaApp) {
        Start-Process -FilePath $OllamaApp
    } else {
        Write-Log "Tray app not found at $OllamaApp; falling back to 'ollama serve'." 'WARN'
        $serve = Get-Command ollama -ErrorAction SilentlyContinue
        if (-not $serve) {
            Write-Log 'ollama is not installed or not on PATH.' 'ERROR'
            return $false
        }
        Start-Process -FilePath $serve.Source -ArgumentList 'serve' -WindowStyle Hidden
    }

    $deadline = (Get-Date).AddSeconds($OllamaTimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 3
        $version = Test-Ollama
        if ($version) {
            Write-Log "Ollama back up (v$version) after restart."
            return $true
        }
    }
    Write-Log "Ollama did not come back within $OllamaTimeoutSeconds s." 'ERROR'
    return $false
}

# ---------------------------------------------------------------- preflight
Write-Log "Lab run $Stamp"
Write-Log "Project: $ProjectRoot"

if (-not (Test-Path $Python)) {
    Write-Log "Virtualenv interpreter missing: $Python" 'ERROR'
    Write-Log 'Create it with:  python -m venv .venv; .venv\Scripts\pip install -r requirements.txt' 'ERROR'
    exit 5
}
Write-Log "Interpreter: $Python"

# Ollama drops integrated GPUs unless this is set. Belt and braces: it is
# persisted at user level, but an unattended run should not depend on that.
$env:OLLAMA_IGPU_ENABLE = '1'

# CrewAI's telemetry exporter blocks for 30 s per batch when it cannot reach
# telemetry.crewai.com. On an unattended run that is pure dead time.
$env:CREWAI_DISABLE_TELEMETRY = 'true'
$env:CREWAI_TELEMETRY_OPT_OUT = 'true'
$env:OTEL_SDK_DISABLED = 'true'
# Unbuffered, so a tailed log shows progress instead of arriving all at once.
$env:PYTHONUNBUFFERED = '1'
$env:PYTHONIOENCODING = 'utf-8'

$offline = $false
if (-not (Start-OllamaIfDead)) {
    if ($FallbackOffline) {
        Write-Log 'Falling back to --offline: deterministic pipeline, no narrative.' 'WARN'
        $offline = $true
    } else {
        Write-Log 'Refusing to run. Pass -FallbackOffline to accept a report with no narrative.' 'ERROR'
        exit 4
    }
}

# ---------------------------------------------------------------- run
$pyArgs = @('main.py')
if ($offline)                          { $pyArgs += '--offline' }
if ($FindingsPath)                     { $pyArgs += @('--input', $FindingsPath) }
if ($OutputDir)                        { $pyArgs += @('--output-dir', $OutputDir) }
if ($TopN)                             { $pyArgs += @('--top-n', "$TopN") }
if ($Model -and -not $offline)         { $pyArgs += @('--model', $Model) }
if ($Strict)                           { $pyArgs += '--strict-narrative' }
if ($StreamAgents)                     { $pyArgs += '--verbose' }
if ($ExtraArgs)                        { $pyArgs += $ExtraArgs }

Write-Log ("Command: `"$Python`" " + ($pyArgs -join ' '))
Write-Log 'Running. Safe to walk away.'

# stdin is redirected from an empty file so that anything which tries to read it
# gets EOF immediately rather than hanging an unattended run forever.
$emptyStdin = Join-Path $env:TEMP "vulntriage-empty-$Stamp.txt"
Set-Content -Path $emptyStdin -Value '' -Encoding utf8
$outFile = "$LogFile.out"
$errFile = "$LogFile.err"

$started = Get-Date
$proc = Start-Process -FilePath $Python -ArgumentList $pyArgs `
    -WorkingDirectory $ProjectRoot `
    -RedirectStandardInput $emptyStdin `
    -RedirectStandardOutput $outFile `
    -RedirectStandardError $errFile `
    -NoNewWindow -Wait -PassThru

$code = $proc.ExitCode
$elapsed = (Get-Date) - $started

# Fold the captured streams into the one log an operator will actually read.
foreach ($pair in @(@{f = $outFile; t = 'stdout' }, @{f = $errFile; t = 'stderr' })) {
    if ((Test-Path $pair.f) -and (Get-Item $pair.f).Length -gt 0) {
        Add-Content -Path $LogFile -Value "`n----- $($pair.t) -----" -Encoding utf8
        Get-Content -Path $pair.f | Add-Content -Path $LogFile -Encoding utf8
        if ($pair.t -eq 'stdout') { Get-Content -Path $pair.f | Write-Host }
        else { Get-Content -Path $pair.f | ForEach-Object { Write-Host $_ -ForegroundColor DarkYellow } }
    }
    Remove-Item $pair.f -Force -ErrorAction SilentlyContinue
}
Remove-Item $emptyStdin -Force -ErrorAction SilentlyContinue

$summary = switch ($code) {
    0 { 'completed, narrative guard clean' }
    1 { 'failed: findings file not found' }
    2 { 'failed: LLM backend unavailable' }
    3 { 'completed, narrative guard flagged a claim (-Strict)' }
    default { "exited $code" }
}
Write-Log ("Finished in {0:mm\:ss} - $summary" -f $elapsed)
Write-Log "Log: $LogFile"
exit $code
