param([string]$SourceRoot = (Split-Path -Parent $PSScriptRoot), [string]$WalletFile = 'BitcoinWallet.ps1', [string]$ResultPath = '')
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
. (Join-Path $SourceRoot $WalletFile)
. (Join-Path $SourceRoot 'BitcoinTransaction.ps1')
. (Join-Path $PSScriptRoot 'TransactionSupport.ps1')
# Validate the independent verifier itself before using it as an oracle.
foreach ($v in (Import-Csv (Join-Path $PSScriptRoot 'fixtures/bip340.csv'))) {
    Test "BIP340 reference verifier official vector $($v.index)" {
        Assert-Equal ([TestCrypto]::VerifySchnorr($v.message,$v.signature,$v.'public key')) ($v.'verification result' -eq 'TRUE')
    }
}
$core=Read-Fixture 'core.json'
foreach ($v in $core.ecdsa) {
    Test "RFC6979 deterministic nonce and ECDSA signature $($v.private)" {
        Assert-Equal (deterministic_k ([TestCrypto]::Number($v.private)) ([TestCrypto]::Number($v.digest))).ToHexString64() $v.nonce
        Assert-Equal (EcdsaSig $v.private $v.data 1) $v.signature
        $der=$v.signature.Substring(0,$v.signature.Length-2)
        Assert-True ([TestCrypto]::VerifyEcdsa($v.digest,$der,$v.public))
        Assert-False ([TestCrypto]::VerifyEcdsa(('00'*32),$der,$v.public))
    }
    Test "Random ECDSA signature independently verifies $($v.private)" {
        $sig=EcdsaSig $v.private $v.data 1 $false
        Assert-True ([TestCrypto]::VerifyEcdsa($v.digest,$sig.Substring(0,$sig.Length-2),$v.public))
    }
    foreach ($flag in @(0,1,0x83)) {
        Test "Schnorr generated signature independently verifies flag=$flag key=$($v.private)" {
            $preimage='0001020304'
            $sig=SchnorrSig $v.private $preimage $flag
            Assert-Equal $sig.Length $(if ($flag) {130} else {128})
            if ($flag) { Assert-Equal $sig.Substring(128) ('{0:x2}' -f $flag) }
            $digest=[TestCrypto]::Tagged('TapSighash',$preimage)
            Assert-True ([TestCrypto]::VerifySchnorr($digest,$sig.Substring(0,128),$v.public.Substring(2)))
            Assert-False ([TestCrypto]::VerifySchnorr(('ff'*32),$sig.Substring(0,128),$v.public.Substring(2)))
        }
    }
}
foreach ($v in $core.messages) {
    Test "Message signature independent fixture bytes=$([Text.Encoding]::UTF8.GetByteCount($v.message))" {
        $address=$core.addresses[0].addresses.P2PKH.address
        Assert-Equal (SignMessage $core.addresses[0].wif $address $v.message) $v.signature
        Assert-True (VerifyMessage $v.signature $address $v.message)
        Assert-False (VerifyMessage $v.signature $address ($v.message+'!'))
    }
}
foreach ($testnet in @($false,$true)) {
    $v=$core.addresses[[int]$testnet]
    foreach ($kind in @('P2PKH','P2SH-P2WPKH','P2WPKH','P2TR')) {
        Test "Message modes $kind testnet=$testnet" {
            $addr=$v.addresses.$kind.address
            if ($kind -eq 'P2TR') {
                $sig=SignMessageP2TR $v.wif $addr 'message'
                Assert-True (VerifyMessageP2TR $sig $addr 'message')
                Assert-False (VerifyMessage $sig $addr 'message')
                Assert-False (VerifyMessageP2TR $sig $addr 'changed')
            } else {
                $sig=SignMessage $v.wif $addr 'message'
                Assert-True (VerifyMessage $sig $addr 'message')
                Assert-False (VerifyMessage $sig $addr 'changed')
                if ($kind -ne 'P2PKH') {
                    $sig=SignMessage $v.wif $addr 'message' -electrum
                    Assert-True (VerifyMessage $sig $addr 'message' -electrum)
                    Assert-False (VerifyMessage $sig $addr 'message')
                }
            }
        }
    }
}
Test 'Message verification rejects malformed and out-of-range signatures' {
    $addr=$core.addresses[0].addresses.P2PKH.address
    Assert-Throws { VerifyMessage '!!' $addr 'm' }
    Assert-Throws { VerifyMessage 'AA==' $addr 'm' } 'length'
    foreach ($header in @(26,31,47,255)) {
        $bytes=[byte[]](@($header)+(@(0)*64))
        Assert-False (VerifyMessage ([Convert]::ToBase64String($bytes)) $addr 'm')
    }
    Assert-Throws { SignMessage $core.addresses[0].wif $core.addresses[1].addresses.P2PKH.address 'm' } 'network'
    Assert-Throws { SignMessage $core.addresses[0].wif $core.addresses[2].addresses.P2PKH.address 'm' }
}
Complete-TestSuite
