# Install or update kodem-cli on Windows.
# Usage: install.ps1 [version]   (or KODEM_CLI_VERSION; KODEM_CLI_INSTALL_DIR overrides the target folder)
# Once installed, kodem-cli updates itself: kodem-cli agent update

param([string]$Version = '')

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Fail([string]$message) {
    [Console]::Error.WriteLine($message)
    exit 1
}

# A 32-bit PowerShell on 64-bit Windows reports x86 in PROCESSOR_ARCHITECTURE and the real one in PROCESSOR_ARCHITEW6432
$arch = $env:PROCESSOR_ARCHITEW6432
if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
if ($arch -ne 'AMD64') { Fail 'kodem-cli: this OS/architecture is not supported.' }

if ($env:KODEM_CLI_VERSION) { $Version = $env:KODEM_CLI_VERSION } elseif (-not $Version) { $Version = 'latest' }
if ($Version -notmatch '^(latest|v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?)$') {
    Fail "ERROR: invalid kodem-cli version: $Version"
}
$url = "https://public.kodemsecurity.com/artifacts/kodem-cli/$Version/kodem-cli-windows-amd64.exe"

# Windows PowerShell 5.1 on older .NET doesn't offer TLS 1.2 by default
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

if ($env:KODEM_CLI_INSTALL_DIR) {
    $dir = $env:KODEM_CLI_INSTALL_DIR
} else {
    $existing = Get-Command kodem-cli -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($existing) { $dir = Split-Path -Parent $existing.Source } else { $dir = Join-Path $HOME '.local\bin' }
}
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$target = Join-Path $dir 'kodem-cli.exe'
$staged = Join-Path $dir ".kodem-cli.new.$PID.exe"

try {
    Write-Host "Downloading kodem-cli-windows-amd64.exe ($Version)..."
    # A dropped connection may not recur, so up to 3 tries; an HTTP error (e.g. no such release) would
    for ($attempt = 1; ; $attempt++) {
        try {
            $response = Invoke-WebRequest -Uri $url -OutFile $staged -PassThru -UseBasicParsing -TimeoutSec 600
            break
        } catch {
            if ($attempt -ge 3 -or $_.Exception.Response) {
                Fail "ERROR: failed to download kodem-cli ($Version) for windows-amd64: $($_.Exception.Message)"
            }
            Start-Sleep -Seconds 2
        }
    }

    # The bucket reports the file's MD5 in x-goog-hash: a mismatch means a broken download
    $expected = ''
    foreach ($hash in @($response.Headers['x-goog-hash'])) {
        foreach ($part in ($hash -split ',')) {
            if ($part.Trim() -like 'md5=*') { $expected = $part.Trim().Substring(4) }
        }
    }
    if (-not $expected) {
        Write-Warning 'the download server sent no checksum; kodem-cli was not verified'
    } else {
        $md5 = [System.Security.Cryptography.MD5]::Create()
        $stream = [System.IO.File]::OpenRead($staged)
        try { $actual = [Convert]::ToBase64String($md5.ComputeHash($stream)) } finally { $stream.Dispose() }
        if ($actual -ne $expected) {
            Fail "ERROR: kodem-cli download failed its checksum (expected md5 $expected, got $actual); not installed"
        }
    }

    # Before it replaces anything: a build that doesn't start must not take the place of one that does
    & $staged --help *> $null
    if ($LASTEXITCODE -ne 0) { Fail "ERROR: the downloaded kodem-cli doesn't run (--help exit $LASTEXITCODE); not installed" }

    # A running .exe can't be overwritten but can be renamed: one fixed <name>.old, replaced next time
    if (Test-Path $target) {
        $old = "$target.old"
        if (Test-Path $old) {
            try { Remove-Item $old -Force } catch { Fail "ERROR: could not replace $old (is an older kodem-cli still running?)" }
        }
        Rename-Item $target $old
        try { Move-Item $staged $target } catch { Rename-Item $old $target; throw }
    } else {
        Move-Item $staged $target
    }
} finally {
    if (Test-Path $staged) { Remove-Item $staged -Force -ErrorAction SilentlyContinue }
}
Write-Host "kodem-cli installed at $target"
# An agent session started before the install doesn't see it: its end-of-turn check doesn't run until a restart
Write-Host "Restart your agent so its Kodem hooks find kodem-cli."

# The user PATH from the registry as stored (REG_EXPAND_SZ, %VARS% kept), written back the same way
$key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
try {
    $userPath = [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if (-not (($userPath -split ';') -contains $dir) -and -not (($env:Path -split ';') -contains $dir)) {
        if ($userPath) { $userPath = "$userPath;$dir" } else { $userPath = $dir }
        $key.SetValue('Path', $userPath, [Microsoft.Win32.RegistryValueKind]::ExpandString)
        # Written to the registry directly, so tell running programs (Explorer starts the new terminals) it changed
        Add-Type -Namespace KodemCli -Name Env -MemberDefinition @'
[DllImport("user32.dll", CharSet = CharSet.Unicode)]
public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
'@
        $result = [UIntPtr]::Zero
        [void][KodemCli.Env]::SendMessageTimeout([IntPtr]0xffff, 0x1A, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$result)
        Write-Host "Added $dir to user PATH. Open a new terminal for it to take effect."
    }
} finally {
    $key.Close()
}

# kodem-cli's code scanner (opengrep) doesn't start without the Visual C++ runtime. Not ours to install
# machine-wide: say what's missing.
if (-not (Test-Path (Join-Path ([Environment]::SystemDirectory) 'vcruntime140.dll'))) {
    Write-Warning "code scans need the Microsoft Visual C++ Redistributable (x64), which isn't installed: https://aka.ms/vs/17/release/vc_redist.x64.exe"
}
