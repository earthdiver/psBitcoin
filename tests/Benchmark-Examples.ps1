# Serial, fresh-process measurements; this script is not part of the regression runner.
param([string]$SourceRoot=(Split-Path -Parent $PSScriptRoot),[ValidateRange(1,20)][int]$Repetitions=3)
$ErrorActionPreference='Stop'
$root=(Get-Item -LiteralPath $SourceRoot).FullName
$runId='examples-benchmark-'+[guid]::NewGuid().ToString('N')
$results=Join-Path $PSScriptRoot "results/$runId"
$null=New-Item -ItemType Directory -Path $results
$workspace=Join-Path ([IO.Path]::GetTempPath()) $runId
$null=New-Item -ItemType Directory -Path $workspace
$exe=(Get-Process -Id $PID).Path
$worker=Join-Path $PSScriptRoot 'BenchmarkExampleWorker.ps1'
function Invoke-Worker([string]$ExampleName,[string]$ModeName,[string]$Cache,[string]$Result) {
    $arguments=@($workspace,$ExampleName,$ModeName,$Cache,$Result) | ForEach-Object { "'"+$_.Replace("'","''")+"'" }
    $command="`$ErrorActionPreference='Stop'; try { & '"+$worker.Replace("'","''")+"' "+($arguments -join ' ')+"; exit 0 } catch { [Console]::Error.WriteLine(`$_); exit 1 }"
    $info=[Diagnostics.ProcessStartInfo]::new()
    $info.FileName=$exe
    $info.Arguments='-NoProfile -NonInteractive -OutputFormat Text -ExecutionPolicy Bypass -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $info.UseShellExecute=$false; $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
    $process=[Diagnostics.Process]::new(); $process.StartInfo=$info
    try {
        $null=$process.Start(); $out=$process.StandardOutput.ReadToEndAsync(); $err=$process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(120000)) { $process.Kill(); throw 'Benchmark process timed out' }
        if ($process.ExitCode -ne 0) { throw "Benchmark failed: $($out.Result) $($err.Result)" }
    } finally { $process.Dispose() }
}
try {
    foreach ($file in @('BitcoinWallet.ps1','wordlist.txt','wordlist_jp.txt')) { Copy-Item -LiteralPath (Join-Path $root $file) -Destination $workspace }
    Copy-Item -LiteralPath (Join-Path $root 'examples') -Destination $workspace -Recurse
    $seedCache=Join-Path $workspace 'seed.bin'
    Invoke-Worker '' 'seed' $seedCache ''
    $records=@()
    $examples=@(Get-ChildItem (Join-Path $root 'examples') -Filter '*.ps1' | Where-Object { $_.BaseName -match '^0[1-7]_' } | Sort-Object Name)
    if ($examples.Count -ne 7) { throw 'Expected examples 01 through 07' }
    for ($trial=1;$trial -le $Repetitions;$trial++) {
        foreach ($example in $examples) {
            $modes=if ($trial % 2) {@('generate','load')} else {@('load','generate')}
            foreach ($mode in $modes) {
                $cache=Join-Path $workspace ('cache-'+[guid]::NewGuid().ToString('N')+'.bin')
                if ($mode -eq 'load') { Copy-Item -LiteralPath $seedCache -Destination $cache }
                $result=Join-Path $results "$trial.$($example.BaseName).$mode.json"
                Invoke-Worker $example.BaseName $mode $cache $result
                $record=Get-Content -LiteralPath $result -Raw | ConvertFrom-Json
                $record | Add-Member NoteProperty Trial $trial
                $records+=$record
                Remove-Item -LiteralPath $cache -Force -ErrorAction SilentlyContinue
            }
            Write-Host "Measured trial $trial/$Repetitions example $($example.BaseName)"
        }
    }
    $hashes=@{}
    foreach ($file in @('BitcoinWallet.ps1','Benchmark-Examples.ps1','BenchmarkExampleWorker.ps1')) {
        $path=if ($file -like 'Benchmark*') {Join-Path $PSScriptRoot $file} else {Join-Path $root $file}
        $hashes[$file]=(Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $report=[pscustomobject]@{RunId=$runId;PowerShell=$PSVersionTable.PSVersion.ToString();OS=[Environment]::OSVersion.ToString();Processor=$env:PROCESSOR_IDENTIFIER;Repetitions=$Repetitions;SourceSHA256=$hashes;Records=$records}
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $results 'summary.json') -Encoding UTF8
    Write-Host "Results: $results"
} finally { Remove-Item -LiteralPath $workspace -Recurse -Force }
