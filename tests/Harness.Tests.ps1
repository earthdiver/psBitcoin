param([string]$SourceRoot = (Split-Path -Parent $PSScriptRoot), [string]$WalletFile = 'BitcoinWallet.ps1', [string]$ResultPath = '')
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
Test 'Assertion helpers reject incorrect values' {
    Assert-Throws { Assert-Equal 'a' 'b' } 'Expected'
    Assert-Throws { Assert-True $false } 'True'
    Assert-Throws { Assert-True @($true,$false) } 'True'
    Assert-Throws { Assert-False $true } 'False'
    Assert-Throws { Assert-Throws { 'no error' } } 'Expected an exception'
    Assert-Throws { Assert-Throws { throw 'wrong reason' } 'right reason' } 'matching'
}
foreach ($name in @('first','second')) {
    Test "Test name does not shadow case variable $name" { Assert-True ($name -in @('first','second')) }
}
foreach ($v in (Read-Fixture 'manifest.json')) {
    Test "Fixture integrity $($v.file)" {
        $actual=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot "fixtures/$($v.file)") -Algorithm SHA256).Hash.ToLowerInvariant()
        Assert-Equal $actual $v.sha256
    }
}
Test 'Official vector counts cannot silently shrink' {
    $b32=Read-Fixture 'bip32.json'; Assert-Equal $b32.valid.Count 17; Assert-Equal $b32.invalid.Count 16
    $b39=Read-Fixture 'bip39.json'; Assert-Equal $b39.english.Count 24; Assert-Equal $b39.japanese.Count 24
    $b350=Read-Fixture 'bip350.json'; Assert-Equal $b350.valid.Count 8; Assert-Equal $b350.invalid.Count 15
    $b143=Read-Fixture 'bip143.json'; Assert-Equal $b143.Count 14
}
Complete-TestSuite
