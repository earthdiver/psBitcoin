param([string]$SourceRoot = (Split-Path -Parent $PSScriptRoot), [string]$WalletFile = 'BitcoinWallet.ps1', [string]$ResultPath = '')
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
. (Join-Path $SourceRoot $WalletFile)
$script:HmacMode='real'
function New-Object {
    param([string]$TypeName)
    if ($TypeName -ne 'Cryptography.HMACSHA512' -or $script:HmacMode -eq 'real') {
        return Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName
    }
    $mock=[pscustomobject]@{Key=$null;Calls=0}
    $mock | Add-Member ScriptMethod ComputeHash {
        param([byte[]]$Data)
        $this.Calls++
        if ($this.Calls -gt 2) { throw 'Unexpected extra derivation attempt' }
        $script:HmacCalls++
        $il=if ($this.Calls -eq 1) {$script:InvalidIL} else {'00'*31+'01'}
        return [byte[]](h2i ($il+('11'*32)))
    }
    $mock | Add-Member ScriptMethod Dispose { $script:HmacDisposed=$true }
    return $mock
}
foreach ($publicOnly in @($false,$true)) {
    foreach ($reason in @('IL >= order','zero child')) {
        Test "BIP32 skips invalid candidate $reason public=$publicOnly" {
            $script:HmacMode='real'
            $private=[HDWallet]::new('000102030405060708090a0b0c0d0e0f')
            $parent=$private
            if ($publicOnly) { $parent=[HDWallet]::new(); $parent.ImportExtendedKey($private.GetExtendedPublicKey(),'m') }
            $script:InvalidIL=if ($reason -eq 'IL >= order') {[ECDSA]::Order.ToHexString64()} else {([ECDSA]::Order-[bigint]::Parse('0'+$private.PrivateKey,'AllowHexSpecifier')).ToHexString64()}
            $script:HmacCalls=0; $script:HmacDisposed=$false; $script:HmacMode='fake'
            try {
                $child=$parent.Derive(0,$false)
                Assert-Equal $child.Index 1; Assert-Equal $child.Path 'm/1'
                Assert-Equal $child.ChainCode ('11'*32)
                Assert-Equal $script:HmacCalls 2
                Assert-True $script:HmacDisposed
            } finally { $script:HmacMode='real' }
        }
    }
}
Test 'Invalid final index terminates without overflow' {
    $parent=[HDWallet]::new('000102030405060708090a0b0c0d0e0f')
    $script:InvalidIL=[ECDSA]::Order.ToHexString64()
    $script:HmacCalls=0; $script:HmacDisposed=$false; $script:HmacMode='fake'
    try {
        Assert-Throws { $parent.Derive([int]::MaxValue,$false) } 'No valid BIP32 child index'
        Assert-Equal $script:HmacCalls 1; Assert-True $script:HmacDisposed
    } finally { $script:HmacMode='real' }
}
foreach ($publicOnly in @($false,$true)) {
    Test "BIP32 accepts zero IL without skipping child public=$publicOnly" {
        $private=[HDWallet]::new('000102030405060708090a0b0c0d0e0f')
        $parent=$private
        if ($publicOnly) { $parent=[HDWallet]::new(); $parent.ImportExtendedKey($private.GetExtendedPublicKey(),'m') }
        $script:InvalidIL='00'*32
        $script:HmacCalls=0; $script:HmacDisposed=$false; $script:HmacMode='fake'
        try {
            $child=$parent.Derive(0,$false)
            Assert-Equal $child.Index 0; Assert-Equal $child.Path 'm/0'
            Assert-Equal $child.PublicKey $parent.PublicKey
            Assert-Equal $child.PrivateKey $parent.PrivateKey
            Assert-Equal $child.ChainCode ('11'*32)
            Assert-Equal $script:HmacCalls 1
            Assert-True $script:HmacDisposed
        } finally { $script:HmacMode='real' }
    }
}
Test 'BIP32 rejects zero IL for master key' {
    $script:InvalidIL='00'*32
    $script:HmacCalls=0; $script:HmacMode='fake'
    try {
        Assert-Throws { [HDWallet]::new('000102030405060708090a0b0c0d0e0f') } 'Result of digest is zero'
        Assert-Equal $script:HmacCalls 1
    } finally { $script:HmacMode='real' }
}
Complete-TestSuite
