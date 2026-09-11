param(
    [string]$SourceRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$ResultPath = '',
    [string]$WalletFile = 'BitcoinWallet.ps1',
    [switch]$PreloadLegacyDecoder
)
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
if ($PreloadLegacyDecoder) {
    # Reproduce an old Add-Type class remaining in the user's PowerShell session.
    Add-Type @'
namespace PsBitcoin {
    public static class AezeedDecoder {
        public static byte[] Decode(byte[] encoded, byte[] passphrase) {
            throw new System.ArgumentException("Unsupported aezeed internal seed version; only LND version 0 is supported.");
        }
    }
}
'@
}
. (Join-Path $SourceRoot 'examples/09_aezeed2seed.ps1') | Out-Null
. (Join-Path $SourceRoot $WalletFile)
# Public, deterministic fixtures from LND v0.19.3-beta and btcd hdkeychain.
# Never use these mnemonics for funds. See reference/aezeed for the generator.
$vectors = Get-Content (Join-Path $PSScriptRoot 'reference/aezeed-vectors.json') -Raw -Encoding UTF8 | ConvertFrom-Json
foreach ($v in $vectors) {
    Test "LND entropy: $($v.Name)" {
        Assert-Equal (GetAezeedSeed $v.Mnemonic -passphrase $v.Passphrase) $v.Entropy
    }
    Test "btcd master xprv/tprv: $($v.Name)" {
        $seed = GetAezeedSeed $v.Mnemonic -passphrase $v.Passphrase
        $main = [HDWallet]::new($seed)
        $test = [HDWallet]::new($seed, $true)
        Assert-Equal $main.Path 'm'
        Assert-Equal $main.Depth 0
        Assert-Equal $main.GetExtendedPrivateKey() $v.MasterXprv
        Assert-Equal $test.GetExtendedPrivateKey() $v.MasterTprv
    }
}
$empty = $vectors[0]
$protected = $vectors[1]
Test 'Legacy and Taproot versions give the same master key for the same entropy' {
    $legacySeed = GetAezeedSeed $empty.Mnemonic
    $taprootSeed = GetAezeedSeed $vectors[4].Mnemonic
    Assert-Equal $legacySeed $taprootSeed
    Assert-Equal ([HDWallet]::new($taprootSeed)).GetExtendedPrivateKey() $empty.MasterXprv
}
Test 'Empty passphrase uses the literal aezeed default' {
    Assert-Equal (GetAezeedSeed $empty.Mnemonic -passphrase 'aezeed') $empty.Entropy
}
Test 'Pipeline preserves both results and order' {
    $actual = @($empty.Mnemonic, $vectors[3].Mnemonic | GetAezeedSeed)
    Assert-Equal $actual.Count 2
    Assert-Equal $actual[0] $empty.Entropy
    Assert-Equal $actual[1] $vectors[3].Entropy
}
Test 'Mnemonic allows uppercase and repeated whitespace' {
    $inputWords = " `t" + ($empty.Mnemonic.ToUpperInvariant() -replace ' ', "`r`n  ") + ' '
    Assert-Equal (GetAezeedSeed $inputWords) $empty.Entropy
}
Test 'Reject wrong passphrase' {
    Assert-Throws { GetAezeedSeed $protected.Mnemonic -passphrase 'wrong' } 'passphrase or authentication'
}
Test 'Reject missing required passphrase' {
    Assert-Throws { GetAezeedSeed $protected.Mnemonic } 'passphrase or authentication'
}
Test 'Passphrase whitespace is significant' {
    Assert-Throws { GetAezeedSeed $vectors[2].Mnemonic -passphrase $vectors[2].Passphrase.Trim() } 'passphrase or authentication'
}
Test 'Passphrase is not BIP39 NFKD-normalized' {
    $decomposed = $vectors[2].Passphrase.Normalize([Text.NormalizationForm]::FormKD)
    Assert-Throws { GetAezeedSeed $vectors[2].Mnemonic -passphrase $decomposed } 'passphrase or authentication'
}
Test 'Reject 23 words' {
    Assert-Throws { GetAezeedSeed (($empty.Mnemonic -split ' ')[0..22] -join ' ') } 'exactly 24'
}
Test 'Reject 25 words' { Assert-Throws { GetAezeedSeed ($empty.Mnemonic + ' abandon') } 'exactly 24' }
Test 'Reject unknown word without echoing the mnemonic' {
    Assert-Throws { GetAezeedSeed ($empty.Mnemonic -replace '^\S+', 'notaword') } '^Unknown aezeed word'
}
Test 'Reject checksum corruption' {
    Assert-Throws { GetAezeedSeed ($empty.Mnemonic -replace '\S+$', 'abandon') } 'checksum'
}
Test 'Reject unsupported external version' {
    Assert-Throws { GetAezeedSeed ($empty.Mnemonic -replace '^\S+', 'zoo') } 'cipher version'
}
Test 'Reject BIP39 as aezeed' {
    $bip39 = ((@('abandon') * 23) + @('art')) -join ' '
    Assert-Throws { GetAezeedSeed $bip39 } 'checksum'
}
Test 'BIP39 seed derivation still matches the published TREZOR vector' {
    $bip39 = ((@('abandon') * 11) + @('about')) -join ' '
    Assert-Equal (GetBIP39Seed $bip39 -passphrase 'TREZOR') (
        'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553' +
        '1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04')
}
Complete-TestSuite
