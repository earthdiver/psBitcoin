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
foreach ($case in @(
    @(252, 'fc'), @(253, 'fdfd00'), @(65535, 'fdffff'),
    @(65536, 'fe00000100'), @(4294967295, 'feffffffff'),
    @(4294967296, 'ff0000000001000000')
)) {
    Check "CompactSize $($case[0])" { (VarInttoStr $case[0]) -ceq $case[1] }
}
if ($script:Failures) { throw "$script:Failures checks failed" }
