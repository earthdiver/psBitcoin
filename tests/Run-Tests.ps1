[CmdletBinding()]
param(
    [string]$SourceRoot = '',
    [string]$PowerShellPath = '',
    [string]$Suite = '*',
    [string]$OutputDirectory = '',
    [ValidateRange(1,3600)][int]$TimeoutSeconds = 300
)
$ErrorActionPreference = 'Stop'
if (-not $SourceRoot) { $SourceRoot = Split-Path -Parent $PSScriptRoot }
if (-not $PowerShellPath) { $PowerShellPath = (Get-Process -Id $PID).Path }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $PSScriptRoot 'results' }
$SourceRoot = (Resolve-Path -LiteralPath $SourceRoot).Path
$files = @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.Tests.ps1' | Where-Object { $_.BaseName -like $Suite } | Sort-Object Name)
if (-not $files.Count) { throw "No test suites matched: $Suite" }
$wallets = @('BitcoinWallet.ps1')
$runId = [Guid]::NewGuid().ToString('N')
$runDirectory = Join-Path $OutputDirectory $runId
$null = New-Item -ItemType Directory -Path $runDirectory -Force
$summaries = [Collections.Generic.List[object]]::new()
$failed = 0
# Fresh process per suite: PowerShell classes, Add-Type, mocks and static caches cannot leak.
foreach ($wallet in $wallets) {
    foreach ($file in $files) {
        $stem = "$($wallet.Replace('.ps1','')).$($file.BaseName)"
        $resultPath = Join-Path $runDirectory "$stem.json"
        $quotedFile = $file.FullName.Replace("'", "''")
        $quotedRoot = $SourceRoot.Replace("'", "''")
        $quotedResult = $resultPath.Replace("'", "''")
        $command = "`$ErrorActionPreference='Stop'; `$ProgressPreference='SilentlyContinue'; `$InformationPreference='SilentlyContinue'; try { & '$quotedFile' -SourceRoot '$quotedRoot' -WalletFile '$wallet' -ResultPath '$quotedResult'; exit 0 } catch { [Console]::Error.WriteLine(`$_); exit 1 }"
        $info = [Diagnostics.ProcessStartInfo]::new()
        $info.FileName = $PowerShellPath
        $info.Arguments = '-NoProfile -NonInteractive -OutputFormat Text -ExecutionPolicy Bypass -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $info
        Write-Host "Running $stem"
        try {
            if (-not $process.Start()) { throw 'Could not start test process' }
            $stdoutTask = $process.StandardOutput.ReadToEndAsync()
            $stderrTask = $process.StandardError.ReadToEndAsync()
            if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
                $process.Kill(); $process.WaitForExit()
                throw "Suite timed out after $TimeoutSeconds seconds"
            }
            $stdout = $stdoutTask.Result
            $stderr = $stderrTask.Result
            [IO.File]::WriteAllText((Join-Path $runDirectory "$stem.log"), $stdout + $stderr)
            if ($stdout) { Write-Host $stdout.TrimEnd() }
            $displayError = ($stderr -replace '(?s)<Objs.*', '' -replace '^#< CLIXML\s*', '').Trim()
            if ($displayError) { Write-Host $displayError -ForegroundColor Red }
            if (-not (Test-Path -LiteralPath $resultPath)) { throw 'Suite did not produce a result (load error or premature exit)' }
            $summary = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
            if ($summary.Total -lt 2) { throw 'Suite did not execute test cases' }
            $summaries.Add($summary)
            if ($process.ExitCode -ne 0 -or $summary.Failed -ne 0) { $failed++ }
        } catch {
            $failed++
            $summaries.Add([pscustomobject]@{ Suite=$file.Name; Wallet=$wallet; Total=0; Failed=1; Error=$_.ToString() })
            Write-Host "ERROR: $stem - $_" -ForegroundColor Red
        } finally { $process.Dispose() }
    }
}
$total = ($summaries | Measure-Object Total -Sum).Sum
$report = [pscustomobject]@{ RunId=$runId; Total=$total; FailedSuites=$failed; Suites=@($summaries.ToArray()) }
$report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $runDirectory 'summary.json') -Encoding UTF8
Write-Host "Total: $total tests; failed suites: $failed. Results: $runDirectory"
if ($failed) { exit 1 }
exit 0
