param([string]$SourceRoot,[string]$Example,[ValidateSet('generate','load','seed')][string]$Mode,[string]$CachePath,[string]$ResultPath)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$env:PSBITCOIN_GENERATOR_CACHE=$CachePath
function Invoke-RestMethod { throw 'Unexpected benchmark network call' }
function Invoke-WebRequest { throw 'Unexpected benchmark network call' }
$wallet='BitcoinWallet.ps1'
. (Join-Path $SourceRoot $wallet)
if ($Mode -eq 'seed') { $null=GetPublicKey ('0'*63+'2'); return }
if ($Mode -eq 'generate' -and (Test-Path $CachePath)) { throw 'Generation measurement requires an absent cache' }
if ($Mode -eq 'load' -and -not (Test-Path $CachePath)) { throw 'Loading measurement requires an existing cache' }
$expected=Get-Content -LiteralPath (Join-Path $SourceRoot "examples/$Example.out") -Raw -Encoding UTF8
$measurements=@()
foreach ($phase in @('first','repeat')) {
    $timer=[Diagnostics.Stopwatch]::StartNew()
    $output=@(& (Join-Path $SourceRoot "examples/$Example.ps1") 6>&1)
    $timer.Stop()
    $actual=((@($output | ForEach-Object { [string]$_ }) -join "`n")+"`n").Replace("`r`n","`n")
    if ($actual -cne $expected) { throw "Output differs from snapshot: $Example $Mode $phase" }
    $measurements+= [pscustomobject]@{Phase=$phase;Milliseconds=$timer.Elapsed.TotalMilliseconds;TablePresent=($null -ne [ECDSA]::GeneratorTable)}
}
[pscustomobject]@{Example=$Example;Mode=$Mode;PowerShell=$PSVersionTable.PSVersion.ToString();Measurements=$measurements} |
    ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
