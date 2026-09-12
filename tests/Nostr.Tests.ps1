param([string]$SourceRoot = (Split-Path -Parent $PSScriptRoot), [string]$WalletFile = 'BitcoinWallet.ps1', [string]$ResultPath = '')
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
. (Join-Path $SourceRoot $WalletFile)
. (Join-Path $SourceRoot 'examples/10_NostrKeys.ps1') | Out-Null

# Published NIP-19 vectors: https://github.com/nostr-protocol/nips/blob/master/19.md
foreach ($case in @(
    @('npub','3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d','npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6'),
    @('nsec','67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa','nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5')
)) {
    $hrp,$hex,$encoded = $case
    Test "NIP-19 $hrp encoding and decoding" {
        Assert-Equal (Bech32_Encode $hex $hrp $false 0) $encoded
        Assert-Equal (Bech32_Decode $encoded) $hex
        Assert-Equal (Bech32_Decode $encoded.ToUpperInvariant() $false) $hex
        $decoded = Bech32_Decode $encoded -WithVersion
        Assert-Equal $decoded.Hrp $hrp
        Assert-Equal $decoded.Program $hex
        Assert-Equal $decoded.Version 0
    }
    Test "NIP-19 $hrp preserves leading zero bytes" {
        foreach ($key in @(('00' * 32), ('00' * 31 + '01'), ('ff' * 32))) {
            Assert-Equal (Bech32_Decode (Bech32_Encode $key $hrp $false 0)) $key
        }
    }
    Test "NIP-19 $hrp rejects invalid inputs" {
        foreach ($length in @(31,33)) {
            Assert-Throws { Bech32_Encode ('ab' * $length) $hrp $false 0 } 'nostr data'
        }
        Assert-Throws { Bech32_Encode $hex $hrp $false 1 } 'nostr data'
        Assert-Throws { Bech32_Encode $hex $hrp $true 0 } 'checksum encoding'
        Assert-Throws { Bech32_Decode $encoded $true } 'checksum encoding'
        Assert-Throws { Bech32_Decode ($encoded.Substring(0,$encoded.Length-1) + 'q') } 'checksum mismatch'
        Assert-Throws { Bech32_Decode ('N' + $encoded.Substring(1)) } 'mixed-case'
    }
}

$mnemonic = 'leader monkey parrot ring guide accident before fence cannon height naive bean'
$expected = @('nsec10allq0gjx7fddtzef0ax00mdps9t2kmtrldkyjfs8l5xruwvh2dq0lhhkp','npub1zutzeysacnf9rru6zqwmxd54mud0k44tst6l70ja5mhv8jjumytsd2x7nu')
Test 'NIP-06 keys match published vector even with caller passphrase' {
    $passphrase = 'TREZOR'
    $actual = @(GetNostrKeys $mnemonic)
    Assert-Equal $actual.Count 2
    Assert-Equal $actual[0] $expected[0]
    Assert-Equal $actual[1] $expected[1]
}
Test 'Nostr mnemonic whitespace is normalized before deriving keys' {
    $actual = @(GetNostrKeys (" `t" + $mnemonic.Replace(' ', '  ') + "`n"))
    Assert-Equal $actual[0] $expected[0]
    Assert-Equal $actual[1] $expected[1]
}
Test 'Nostr explicit passphrase uses normalized BIP39 seed' {
    $composed = [string][char]0x00e9
    $decomposed = 'e' + [char]0x0301
    $actual = @(GetNostrKeys $mnemonic -passphrase $composed)
    $normalized = @(GetNostrKeys $mnemonic -passphrase $decomposed)
    Assert-Equal $actual[0] $normalized[0]
    Assert-Equal $actual[1] $normalized[1]
    Assert-True ($actual[0] -cne $expected[0])
    $wallet = [HDWallet]::new((GetBIP39Seed $mnemonic $composed))
    $child = Get-TestWalletPath $wallet "m/44'/1237'/0'/0/0"
    Assert-Equal (Bech32_Decode $actual[0]) $child.PrivateKey
    Assert-Equal (Bech32_Decode $actual[1]) $child.PublicKey.Substring(2)
}
Test 'Nostr invalid mnemonic is rejected' {
    Assert-Throws { GetNostrKeys 'not a valid mnemonic' } 'invalid BIP39 mnemonic'
}
Complete-TestSuite
