param(
    [string]$SourceRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$WalletFile = 'BitcoinWallet.ps1'
)
$ErrorActionPreference = 'Stop'
. (Join-Path $SourceRoot $WalletFile)
# Public BIP32 test seed; never use this seed for funds.
$privateParent = [HDWallet]::new('000102030405060708090a0b0c0d0e0f')
$publicParent = [HDWallet]::new()
$publicParent.ImportExtendedKey($privateParent.GetExtendedPublicKey(), 'm')
# Inject IL=0 instead of waiting for a naturally occurring 256-bit edge case.
function New-Object {
    param([string]$TypeName)
    if ($TypeName -ne 'Cryptography.HMACSHA512') {
        return Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName
    }
    $mock = [pscustomobject]@{ Key = $null; Calls = 0 }
    $mock | Add-Member ScriptMethod ComputeHash {
        param([byte[]]$Data)
        $this.Calls++
        if ($this.Calls -gt 1) { throw 'IL=0 incorrectly skipped the requested index' }
        return [byte[]]((@(0) * 32) + (@(17) * 32))
    }
    $mock | Add-Member ScriptMethod Dispose {}
    return $mock
}
try {
    foreach ($parent in @($privateParent, $publicParent)) {
        $child = $parent.Derive(0, $false)
        if ($child.Index -ne 0 -or $child.Path -cne 'm/0') {
            throw 'IL=0 changed the requested index'
        }
        if ($child.PublicKey -cne $parent.PublicKey -or
            $child.PrivateKey -cne $parent.PrivateKey -or
            $child.ChainCode -cne ('11' * 32)) {
            throw 'IL=0 produced the wrong child key or chain code'
        }
        "PASS: IL=0, publicOnly=$(-not $parent.PrivateKey)"
    }
    # Master IL=0 must still be rejected.
    $rejected = $false
    try { $null = [HDWallet]::new('000102030405060708090a0b0c0d0e0f') }
    catch { $rejected = $_.Exception.Message -match 'Result of digest is zero' }
    if (-not $rejected) { throw 'Master IL=0 must be rejected' }
    'PASS: master IL=0 remains rejected'
} finally {
    Remove-Item Function:New-Object
}
