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
    foreach ($purpose in @(0,49,84)) {
        $c = $w.Derive($purpose, $true)
        foreach ($publicOnly in @($false, $true)) {
            Check "Roundtrip $($c.Path), testnet=$testnet, public=$publicOnly" {
                $key = if ($publicOnly) { $c.GetExtendedPublicKey() } else { $c.GetExtendedPrivateKey() }
                $import = [HDWallet]::new()
                $import.ImportExtendedKey($key, $c.Path)
                $actual = if ($publicOnly) { $import.GetExtendedPublicKey() } else { $import.GetExtendedPrivateKey() }
                $actual -ceq $key
            }
        }
    }

}
if ($script:Failures) { throw "$script:Failures checks failed" }
