param([string]$SourceRoot = (Split-Path -Parent $PSScriptRoot), [string]$WalletFile = 'BitcoinWallet.ps1', [string]$ResultPath = '')
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
. (Join-Path $SourceRoot $WalletFile)
$vectors = Read-Fixture 'bip32.json'
foreach ($v in $vectors.valid) {
    Test "BIP32 derive $($v.seed.Substring(0,8)) $($v.path)" {
        $root=[HDWallet]::new($v.seed)
        $node=Get-TestWalletPath $root $v.path
        # Force xprv/xpub: this project intentionally exports z-keys for m/0'.
        Assert-Equal ($node.GetExtendedPrivateKey($false,$true)) $v.private
        Assert-Equal ($node.GetExtendedPublicKey($false,$true)) $v.public
        Assert-Equal $node.Path $v.path
        Assert-Equal $node.Depth (($v.path -split '/').Count-1)
    }
    foreach ($publicOnly in @($false,$true)) {
        Test "BIP32 import $($v.seed.Substring(0,8)) $($v.path) public=$publicOnly" {
            $key=if ($publicOnly) {$v.public} else {$v.private}
            $node=[HDWallet]::new()
            $node.ImportExtendedKey($key,$v.path)
            Assert-Equal ($node.GetExtendedPublicKey($false,$true)) $v.public
            if (-not $publicOnly) { Assert-Equal ($node.GetExtendedPrivateKey($false,$true)) $v.private }
            else { Assert-True ([string]::IsNullOrEmpty($node.PrivateKey)) }
        }
    }
}
foreach ($v in $vectors.invalid) {
    Test "BIP32 invalid key: $($v.reason)" {
        Assert-Throws { ([HDWallet]::new()).ImportExtendedKey($v.key,'m') }
    }
}
foreach ($seed in @('', ('00'*15), ('00'*65), ('gg'*16), ('0'*33))) {
    Test "Invalid seed length/encoding $($seed.Length) $($seed.Substring(0,[Math]::Min(2,$seed.Length)))" {
        Assert-Throws { [HDWallet]::new($seed) } 'seed'
    }
}
Test 'Uppercase seed produces same keys' {
    Assert-Equal ([HDWallet]::new('ABCDEF0123456789ABCDEF0123456789')).GetExtendedPrivateKey() ([HDWallet]::new('abcdef0123456789abcdef0123456789')).GetExtendedPrivateKey()
}
Test 'Public and private non-hardened derivation agree' {
    $root=[HDWallet]::new($vectors.valid[0].seed)
    $pub=[HDWallet]::new(); $pub.ImportExtendedKey($root.GetExtendedPublicKey(),'m')
    foreach ($index in @(0,1,2,2147483647)) {
        Assert-Equal ($pub.Derive($index,$false).GetExtendedPublicKey($false,$true)) ($root.Derive($index,$false).GetExtendedPublicKey($false,$true))
    }
    Assert-Throws { $pub.Derive(0,$true) } 'hardened'
    Assert-Throws { $root.Derive(-1,$false) } 'index'
    $root.Depth=255
    Assert-Throws { $root.Derive(0,$false) } 'depth'
}
Test 'Cache distinguishes networks and hardened children' {
    $root=[HDWallet]::new($vectors.valid[0].seed)
    $a=$root.Derive(7,$false,$false); $b=$root.Derive(7,$false,$true); $h=$root.Derive(7,$true)
    Assert-True ([object]::ReferenceEquals($a,$root.Derive(7,$false,$false)))
    Assert-False ([object]::ReferenceEquals($a,$b))
    Assert-Equal $a.PrivateKey $b.PrivateKey
    Assert-True ($a.PrivateKey -cne $h.PrivateKey)
    Assert-False $a.Testnet; Assert-True $b.Testnet
}
Test 'Disposing child clears descendants and allows rederivation' {
    $root=[HDWallet]::new($vectors.valid[0].seed)
    $child=$root.Derive(1,$false); $grandchild=$child.Derive(2,$false)
    $expected=$child.GetExtendedPrivateKey()
    $child.Dispose()
    Assert-True ([string]::IsNullOrEmpty($grandchild.PrivateKey))
    Assert-Equal $root.Derive(1,$false).GetExtendedPrivateKey() $expected
}
foreach ($testnet in @($false,$true)) {
    foreach ($purpose in @(44,49,84,86)) {
        Test "Account export/import purpose=$purpose testnet=$testnet" {
            $root=[HDWallet]::new($vectors.valid[0].seed,$testnet)
            $node=$root.Derive($purpose,$true).Derive([int]$testnet,$true).Derive(0,$true)
            foreach ($key in @($node.GetExtendedPrivateKey(),$node.GetExtendedPublicKey())) {
                $copy=[HDWallet]::new(); $copy.ImportExtendedKey($key,$node.Path)
                Assert-Equal $copy.GetExtendedPublicKey() $node.GetExtendedPublicKey()
                Assert-Equal $copy.Testnet $testnet
                Assert-Throws { ([HDWallet]::new()).ImportExtendedKey($key,$node.Path,(-not $testnet)) } 'network'
            }
        }
    }
    foreach ($scriptType in @(1,2)) {
        Test "BIP48 multisig prefix script=$scriptType testnet=$testnet" {
            $node=([HDWallet]::new($vectors.valid[0].seed,$testnet)).Derive(48,$true).Derive([int]$testnet,$true).Derive(0,$true).Derive($scriptType,$true)
            $expected=if ($testnet) { if ($scriptType -eq 1) {'Upub'} else {'Vpub'} } else { if ($scriptType -eq 1) {'Ypub'} else {'Zpub'} }
            Assert-Equal $node.GetExtendedPublicKey().Substring(0,4) $expected
            $copy=[HDWallet]::new(); $copy.ImportExtendedKey($node.GetExtendedPublicKey(),$node.Path)
            Assert-Equal $copy.GetExtendedPublicKey() $node.GetExtendedPublicKey()
        }
    }
}
# SLIP-format keys support export/import at depths before the account level.
foreach ($testnet in @($false,$true)) {
    foreach ($purpose in @(0,49,84)) {
        foreach ($publicOnly in @($false,$true)) {
            Test "Shallow extended key round-trip purpose=$purpose testnet=$testnet public=$publicOnly" {
                $node=([HDWallet]::new($vectors.valid[0].seed,$testnet)).Derive($purpose,$true)
                $key=if ($publicOnly) {$node.GetExtendedPublicKey()} else {$node.GetExtendedPrivateKey()}
                $copy=[HDWallet]::new(); $copy.ImportExtendedKey($key,$node.Path)
                $actual=if ($publicOnly) {$copy.GetExtendedPublicKey()} else {$copy.GetExtendedPrivateKey()}
                Assert-Equal $actual $key
                Assert-Equal $copy.Testnet $testnet
            }
        }
    }
    Test "Generic derivation inherits network testnet=$testnet" {
        $root=[HDWallet]::new($vectors.valid[0].seed,$testnet)
        Assert-Equal $root.Derive(123,$true).Derive(1,$true).Testnet $testnet
    }
    Test "Generic derivation allows explicit network testnet=$testnet" {
        $root=[HDWallet]::new($vectors.valid[0].seed,$testnet)
        Assert-Equal $root.Derive(123,$true).Derive(1,$true,$testnet).Testnet $testnet
    }
}
Test 'BIP84 coin type selects testnet' {
    $root=[HDWallet]::new($vectors.valid[0].seed)
    Assert-True $root.Derive(84,$true).Derive(1,$true).Testnet
}
Test 'BIP84 rejects network contradicting coin type' {
    $root=[HDWallet]::new($vectors.valid[0].seed)
    Assert-Throws { $root.Derive(84,$true).Derive(1,$true,$false) } 'coin type'
}
Test 'Reimport rejects initialized child and preserves parent cache' {
    $root=[HDWallet]::new($vectors.valid[0].seed)
    $other=[HDWallet]::new('ffffffffffffffffffffffffffffffff')
    $child=$root.Derive(0,$false)
    $expected=$child.GetExtendedPrivateKey()
    Assert-Throws { $child.ImportExtendedKey($other.Derive(0,$false).GetExtendedPrivateKey(),'m/0') } 'already initialized'
    Assert-Equal $child.GetExtendedPrivateKey() $expected
    Assert-Equal $root.Derive(0,$false).GetExtendedPrivateKey() $expected
}
Complete-TestSuite
