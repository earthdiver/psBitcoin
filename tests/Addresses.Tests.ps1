param([string]$SourceRoot = (Split-Path -Parent $PSScriptRoot), [string]$WalletFile = 'BitcoinWallet.ps1', [string]$ResultPath = '')
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
. (Join-Path $SourceRoot $WalletFile)
. (Join-Path $SourceRoot 'BitcoinTransaction.ps1')
$core=Read-Fixture 'core.json'
foreach ($v in $core.addresses) {
    $label="$($v.private.Substring(56)) testnet=$($v.testnet)"
    Test "Public key and WIF oracle $label" {
        Assert-Equal (GetPublicKey $v.private) $v.public
        Assert-Equal (GetPublicKey $v.private -UnCompressed) $v.uncompressed
        Assert-Equal (DecompressPublicKey $v.public) $v.uncompressed
        Assert-Equal (GetWIF $v.private -Testnet:$v.testnet) $v.wif
        Assert-Equal (GetWIF $v.private -Testnet:$v.testnet -UnCompressed) $v.wifUC
        foreach ($key in @($v.wif,$v.wifUC)) {
            $decoded=DecodeWIF $key
            Assert-Equal $decoded.PrivateKey $v.private
            Assert-Equal $decoded.Testnet $v.testnet
            Assert-Equal (GetPublicKeyFromWIF $key) $(if ($decoded.Compressed) {$v.public} else {$v.uncompressed})
        }
    }
    foreach ($kind in @('P2PKH','P2SH','P2SH-P2WPKH','P2SH-P2WSH','P2WPKH','P2WSH','P2TR','P2TR-SP')) {
        Test "Address and script oracle $kind $label" {
            $expected=$v.addresses.$kind
            Assert-Equal (& "GetAddress$kind" $v.public -Testnet:$v.testnet) $expected.address
            Assert-Equal (ConvertAddressToScriptPubKey $expected.address) $expected.script
            Assert-Equal (AssertBitcoinAddress $expected.address) $expected.address
        }
    }
    Test "Taproot tweaked private key matches output $label" {
        $tweaked=GetTweakedWIF $v.wif
        Assert-Equal (GetPublicKeyFromWIF $tweaked).Substring(2) $v.addresses.P2TR.script.Substring(4)
        Assert-Equal (DecodeWIF $tweaked).Testnet $v.testnet
    }
}
$bech=Read-Fixture 'bip350.json'
foreach ($v in $bech.valid) {
    Test "BIP350 address $($v.address)" {
        $version=if ($v.script.StartsWith('00')) {0} else {[Convert]::ToInt32($v.script.Substring(0,2),16)-80}
        Assert-Equal (ConvertAddressToScriptPubKey $v.address) $v.script
        Assert-Equal (Bech32_Decode $v.address) $v.script.Substring(4)
        Assert-Equal (Bech32_Encode $v.script.Substring(4) $v.address.Substring(0,2).ToLowerInvariant() ($version -ne 0) $version) $v.address.ToLowerInvariant()
    }
}
foreach ($v in $bech.invalid) {
    Test "BIP350 rejects $($v.reason) $($v.address)" { Assert-Throws { Bech32_Decode $v.address } }
}
foreach ($v in (Read-Fixture 'bip86.json')) {
    Test "BIP86 official $($v.path)" {
        $root=[HDWallet]::new('5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4')
        $node=Get-TestWalletPath $root $v.path
        Assert-Equal $node.GetExtendedPrivateKey() $v.xprv
        Assert-Equal $node.GetExtendedPublicKey() $v.xpub
        if ($v.address) {
            Assert-Equal $node.PublicKey.Substring(2) $v.internal_key
            Assert-Equal $node.GetAddressP2TR() $v.address
        }
    }
}
foreach ($key in @(('00'*32),('ff'*32),'1',('zz'*32))) {
    Test "Reject invalid private key $($key.Substring(0,[Math]::Min(4,$key.Length)))" {
        Assert-Throws { AssertPrivateKey $key } 'private key'
        Assert-Throws { GetWIF $key } 'private key'
        Assert-Throws { GetPublicKey $key }
    }
}
foreach ($key in @('', ('05'+('00'*32)),('02'+('ff'*32)),('04'+('00'*64)))) {
    Test "Reject invalid public key $($key.Length) $($key.Substring(0,[Math]::Min(2,$key.Length)))" {
        Assert-Throws { AssertPublicKey $key }
        Assert-Throws { GetAddressP2PKH $key }
    }
}
Test 'Base58Check independent known payload and checksum corruption' {
    Assert-Equal (Base58Check_Encode ('00'+'751e76e8199196d454941c45d1b3a323f1433bd6')) '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH'
    Assert-Equal (Base58Check_Decode '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH') ('00'+'751e76e8199196d454941c45d1b3a323f1433bd6')
    Assert-Throws { Base58Check_Decode '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMJ' } 'checksum'
    Assert-Throws { Base58Check_Decode '0OIl' } 'character'
    Assert-Throws { Base58Address_Decode (Base58Check_Encode ('00'*20)) } 'payload'
    Assert-Throws { DecodeWIF $core.addresses[0].wifUC -Compressed } 'compressed'
}
Test 'Compressed keys required for witness addresses' {
    foreach ($command in @('GetAddressP2WPKH','GetAddressP2WSH','GetAddressP2SH-P2WPKH','GetAddressP2SH-P2WSH','GetAddressP2TR')) {
        Assert-Throws { & $command $core.addresses[0].uncompressed } 'compressed'
    }
}
Test 'URI formatting is invariant and escapes query values' {
    $address=$core.addresses[0].addresses.P2PKH.address
    $culture=[Threading.Thread]::CurrentThread.CurrentCulture
    try {
        [Threading.Thread]::CurrentThread.CurrentCulture=[Globalization.CultureInfo]::GetCultureInfo('fr-FR')
        Assert-Equal (GetURI $address -amount ([decimal]1/100000000) -label 'a & b' -message 'x=y') "bitcoin:${address}?amount=0.00000001&label=a%20%26%20b&message=x%3Dy"
        Assert-Equal (GetURI $address) "bitcoin:$address"
        Assert-Equal (GetURI $address -amount 0) "bitcoin:${address}?amount=0"
        Assert-Throws { GetURI $address -amount -1 } 'amount'
        Assert-Throws { GetURI $address -amount 21000001 } 'amount'
        Assert-Throws { GetURI $address -amount ([decimal]1/1000000000) } 'decimal'
    } finally { [Threading.Thread]::CurrentThread.CurrentCulture=$culture }
}
Complete-TestSuite
