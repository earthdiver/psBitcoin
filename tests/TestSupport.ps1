# Shared, dependency-free test harness (Windows PowerShell 5.1 / PowerShell 7).
$ErrorActionPreference = 'Stop'
$script:TestResults = [Collections.Generic.List[object]]::new()
$script:TestFailureCount = 0
$script:UnexpectedNetworkCalls = 0
function Invoke-RestMethod { $script:UnexpectedNetworkCalls++; throw 'Unexpected network access in offline test' }
function Invoke-WebRequest { $script:UnexpectedNetworkCalls++; throw 'Unexpected network access in offline test' }

function Assert-Equal($Actual, $Expected, [string]$Because = '') {
    if ($null -eq $Actual -and $null -eq $Expected) { return }
    if ([string]$Actual -cne [string]$Expected) {
        throw "Expected <$Expected>, got <$Actual>. $Because"
    }
}
function Assert-True($Actual, [string]$Because = '') {
    if ($Actual -isnot [bool] -or -not $Actual) { throw "Expected boolean True. $Because" }
}
function Assert-False($Actual, [string]$Because = '') {
    if ($Actual -isnot [bool] -or $Actual) { throw "Expected boolean False. $Because" }
}
function Assert-Throws([scriptblock]$Action, [string]$Pattern = '.') {
    $caught = $null
    try { $null = & $Action } catch { $caught = $_ }
    if ($null -eq $caught) { throw 'Expected an exception, but operation succeeded' }
    if ($caught.Exception.Message -notmatch $Pattern) {
        throw "Expected exception matching <$Pattern>, got <$($caught.Exception.Message)>"
    }
}
function Test([string]$TestName, [scriptblock]$TestBody) {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $failure = $null
    try { $null = & $TestBody } catch { $failure = $_.ToString(); $script:TestFailureCount++ }
    $timer.Stop()
    $script:TestResults.Add([pscustomobject]@{
        Name = $TestName; Passed = ($null -eq $failure); Error = $failure; Milliseconds = $timer.ElapsedMilliseconds
    })
    if ($null -ne $failure) { Write-Host "FAIL: $TestName - $failure" -ForegroundColor Red }
}
function Complete-TestSuite {
    Test 'No unexpected HTTP calls' { Assert-Equal $script:UnexpectedNetworkCalls 0 }
    $result = [pscustomobject]@{
        Suite = [IO.Path]::GetFileName($MyInvocation.ScriptName)
        Wallet = $WalletFile; PowerShell = $PSVersionTable.PSVersion.ToString()
        Total = $script:TestResults.Count; Failed = $script:TestFailureCount; Tests = @($script:TestResults.ToArray())
    }
    if ($ResultPath) { $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ResultPath -Encoding UTF8 }
    Write-Host "$($result.Suite): $($result.Total) tests, $($result.Failed) failed ($WalletFile)"
    if ($script:TestFailureCount) { throw "$script:TestFailureCount tests failed" }
}
function Read-Fixture([string]$Name) {
    Get-Content -LiteralPath (Join-Path $PSScriptRoot "fixtures/$Name") -Raw -Encoding UTF8 | ConvertFrom-Json
}
function Get-TestWalletPath($RootWallet, [string]$Path) {
    $node = $RootWallet
    foreach ($part in ($Path -split '/' | Select-Object -Skip 1)) {
        $node = $node.Derive([int]($part.TrimEnd("'")), $part.EndsWith("'"))
    }
    return $node
}
