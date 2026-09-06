param(
    [string]$SourceRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$WalletFile = 'BitcoinWallet.ps1'
)
$ErrorActionPreference = 'Stop'
. (Join-Path $SourceRoot $WalletFile)
. (Join-Path $SourceRoot 'BitcoinTransaction.ps1')
$script:Failures = 0
function Check($Name, [scriptblock]$Test) {
    try {
        if (-not (& $Test)) { throw 'unexpected result' }
        "PASS: $Name"
    } catch {
        $script:Failures++
        "FAIL: $Name - $($_.Exception.Message)"
    }
}
# Public BIP32 test seed; never use this seed for funds.
foreach ($testnet in @($false, $true)) {
    $w = [HDWallet]::new('000102030405060708090a0b0c0d0e0f', $testnet)
    Check "Generic path inherits network=$testnet" {
        $w.Derive(123, $true).Derive(1, $true).Testnet -eq $testnet
    }
    Check "Generic path allows explicit network=$testnet" {
        $w.Derive(123, $true).Derive(1, $true, $testnet).Testnet -eq $testnet
    }
}
Check 'BIP84 coin type still selects testnet' { $w.Derive(84,$true).Derive(1,$true).Testnet }
Check 'BIP84 contradictory network remains rejected' {
    try { $null = $w.Derive(84,$true).Derive(1,$true,$false); return $false }
    catch { return $_.Exception.Message -match 'coin type' }
}
if ($script:Failures) { throw "$script:Failures checks failed" }
