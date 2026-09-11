param([string]$SourceRoot = (Split-Path -Parent $PSScriptRoot), [string]$WalletFile = 'BitcoinWallet.ps1', [string]$ResultPath = '')
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
. (Join-Path $SourceRoot $WalletFile)
$vectors = Read-Fixture 'bip39.json'
foreach ($language in @('english','japanese')) {
    $japanese = $language -eq 'japanese'
    $index = 0
    foreach ($v in $vectors.$language) {
        Test "BIP39 $language vector $index entropy -> mnemonic" {
            Assert-Equal (GetMnemonic (h2i $v[0]) -Japanese:$japanese) $v[1]
        }
        Test "BIP39 $language vector $index validation and seed" {
            Assert-True (ValidateMnemonic $v[1] -Japanese:$japanese)
            Assert-Equal (GetBIP39Seed $v[1] 'TREZOR' -Japanese:$japanese) $v[2]
        }
        Test "BIP39 $language vector $index master key" {
            Assert-Equal ([HDWallet]::new($v[2])).GetExtendedPrivateKey() $v[3]
        }
        $index++
    }
    Test "Wordlist $language size and uniqueness" {
        $words = @(GetBIP39Wordlist -Japanese:$japanese)
        Assert-Equal $words.Count 2048
        $unique=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($word in $words) { $null=$unique.Add($word) }
        Assert-Equal $unique.Count 2048
    }
    foreach ($length in @(16,20,24,28,32)) {
        Test "All supported entropy sizes $language $length with pipeline" {
            $bytes = [byte[]](0..($length-1))
            $mnemonic = GetMnemonic $bytes -Japanese:$japanese
            Assert-Equal ($bytes | GetMnemonic -Japanese:$japanese) $mnemonic
            Assert-Equal ($mnemonic -split '\s+').Count ($length*3/4)
            Assert-True (ValidateMnemonic $mnemonic -Japanese:$japanese)
        }
    }
}
foreach ($length in @(0,1,15,17,19,21,23,25,27,29,31,33,64)) {
    Test "Reject entropy length $length" { Assert-Throws { GetMnemonic ([byte[]]::new($length)) } 'entropy length' }
}
$mnemonic = $vectors.english[0][1]
foreach ($bad in @('', 'abandon', ('abandon '*12).Trim(), ($mnemonic -replace 'about','unknown'), $mnemonic.ToUpperInvariant(), ($mnemonic+' about'))) {
    Test "Invalid mnemonic <$bad>" { Assert-False (ValidateMnemonic $bad) }
}
Test 'Invalid mnemonic cannot produce a seed' { Assert-Throws { GetBIP39Seed 'invalid' } 'mnemonic' }
Test 'Whitespace normalization and Unicode passphrase NFKD' {
    Assert-Equal (GetBIP39Seed (" `t"+($mnemonic -replace ' ',"`r`n ")+' ') 'TREZOR') $vectors.english[0][2]
    Assert-Equal (GetBIP39Seed $mnemonic ([string][char]0xe9)) (GetBIP39Seed $mnemonic ("e"+[char]0x301))
    Assert-True ((GetBIP39Seed $mnemonic 'a') -cne (GetBIP39Seed $mnemonic ' a'))
    $jp=$vectors.japanese[0][1]
    Assert-True (ValidateMnemonic $jp.Normalize([Text.NormalizationForm]::FormC) -Japanese)
}
foreach ($case in @(
    @(1,20,'0c60c80f961f0e71f3a9b524af6012062fe037a6'),
    @(2,20,'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957')
)) {
    Test "RFC6070 PBKDF2 iterations=$($case[0])" {
        $digest=[Security.Cryptography.HMACSHA1]::new()
        try { Assert-Equal (PBKDF2 'password' 'salt' $case[0] $case[1] $digest) $case[2] } finally { $digest.Dispose() }
    }
}
Test 'PBKDF2 rejects invalid parameters' {
    $digest=[Security.Cryptography.HMACSHA512]::new()
    try {
        Assert-Throws { PBKDF2 'p' 's' 0 64 $digest } 'iterations'
        Assert-Throws { PBKDF2 'p' 's' 1 0 $digest } 'keyLength'
        Assert-Throws { PBKDF2 'p' 's' 1 64 $null } 'digest'
    } finally { $digest.Dispose() }
}
Complete-TestSuite
