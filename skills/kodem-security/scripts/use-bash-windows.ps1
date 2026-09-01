# Windows entry point for kodem-security shell scripts.
# Locates Git Bash and forwards to the requested .sh script.
# Usage: use-bash-windows.ps1 <script-name>.sh [args...]

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Script,

    [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
    [string[]]$ScriptArgs
)

$ErrorActionPreference = 'Stop'

$candidates = @(
    "$env:ProgramFiles\Git\bin\bash.exe",
    "${env:ProgramFiles(x86)}\Git\bin\bash.exe",
    "$env:LOCALAPPDATA\Programs\Git\bin\bash.exe"
)
$bash = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1

if (-not $bash) {
    $gitCmd = Get-Command git -ErrorAction SilentlyContinue
    if ($gitCmd) {
        $maybe = Join-Path (Split-Path -Parent $gitCmd.Source) 'bash.exe'
        if (Test-Path $maybe) { $bash = $maybe }
    }
}

if (-not $bash) {
    Write-Error "Git Bash not found. Install Git for Windows from https://git-scm.com/download/win and retry."
    exit 1
}

$scriptPath = Join-Path $PSScriptRoot $Script
if (-not (Test-Path $scriptPath)) {
    Write-Error "Script not found: $scriptPath"
    exit 1
}

if ($ScriptArgs) {
    & $bash $scriptPath @ScriptArgs
} else {
    & $bash $scriptPath
}
exit $LASTEXITCODE
