param([string]$SourceRoot = (Split-Path -Parent $PSScriptRoot), [string]$WalletFile = 'BitcoinWallet.ps1', [string]$ResultPath = '')
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
. (Join-Path $SourceRoot $WalletFile)
. (Join-Path $SourceRoot 'BitcoinTransaction.ps1')
. (Join-Path $SourceRoot 'SeedQR.ps1')
function QRCode { param($Payload,$ECCLevel,$Width,$Height) [BitConverter]::ToString([Text.Encoding]::UTF8.GetBytes([string]$Payload)) }
$core=Read-Fixture 'core.json'
$a=$core.addresses[0]; $b=$core.addresses[2]
$cases=@(
    @{Command='h2i'; Values=@('00','0102')},
    @{Command='b2i'; Values=@('00000000','0000000100000010')},
    @{Command='Hash160'; Values=@('00','0102')},
    @{Command='Hash256'; Values=@('00','0102')},
    @{Command='GetPublicKey'; Values=@($a.private,$b.private)},
    @{Command='GetPublicKeyFromWIF'; Values=@($a.wif,$b.wif)},
    @{Command='DecompressPublicKey'; Values=@($a.public,$b.public)},
    @{Command='GetWIF'; Values=@($a.private,$b.private)},
    @{Command='Base58Check_Encode'; Values=@('0001','0002')},
    @{Command='Base58Check_Decode'; Values=@($a.wif,$b.wif)},
    @{Command='Base58Address_Decode'; Values=@($a.addresses.P2PKH.address,$b.addresses.P2PKH.address)},
    @{Command='Bech32_Encode'; Values=@($a.addresses.P2WPKH.script.Substring(4),$b.addresses.P2WPKH.script.Substring(4));Options=@{hrp='bc';m=$false;v=0}},
    @{Command='Bech32_Decode'; Values=@($a.addresses.P2WPKH.address,$b.addresses.P2WPKH.address)},
    @{Command='AssertBitcoinAddress'; Values=@($a.addresses.P2PKH.address,$b.addresses.P2PKH.address)},
    @{Command='GetTweak'; Values=@($a.public,$b.public)},
    @{Command='GetTweakedWIF'; Values=@($a.wif,$b.wif)},
    @{Command='GetURI'; Values=@($a.addresses.P2PKH.address,$b.addresses.P2PKH.address)},
    @{Command='ConvertAddressToScriptPubKey'; Values=@($a.addresses.P2PKH.address,$b.addresses.P2PKH.address)},
    @{Command='descsum_create'; Values=@('raw(deadbeef)','raw(51)')},
    @{Command='descsum_check'; Values=@('raw(deadbeef)#89f8spxm','invalid')},
    @{Command='Mnemonic2QRCode'; Values=@((Read-Fixture 'bip39.json').english[0][1],(Read-Fixture 'bip39.json').english[1][1])},
    @{Command='Mnemonic2CompactQRCode'; Values=@((Read-Fixture 'bip39.json').english[0][1],(Read-Fixture 'bip39.json').english[1][1])}
)
foreach ($kind in @('P2PKH','P2SH','P2WPKH','P2WSH','P2SH-P2WPKH','P2SH-P2WSH','P2TR','P2TR-SP')) {
    $cases+=@{Command="GetAddress$kind";Values=@($a.public,$b.public)}
}
foreach ($case in $cases) {
    Test "Advertised pipeline preserves every input: $($case.Command)" {
        $command=$case.Command
        $options=@{}
        if ($case.Options) { $options=$case.Options }
        $expected=@(foreach ($value in $case.Values) { & $command $value @options })
        $actual=@($case.Values | & $command @options)
        Assert-Equal $actual.Count $expected.Count 'Pipeline must not silently discard earlier items'
        Assert-Equal ($actual -join '|') ($expected -join '|') 'Pipeline must preserve input order'
    }
}
Test 'ValidateMnemonic emits a result for every pipeline input' {
    $mnemonic=(Read-Fixture 'bip39.json').english[0][1]
    $actual=@('invalid',$mnemonic | ValidateMnemonic)
    Assert-Equal $actual.Count 2
    Assert-False $actual[0]
    Assert-True $actual[1]
}
Test 'GetBIP39Seed emits both seeds in input order' {
    $vectors=Read-Fixture 'bip39.json'
    $mnemonics=@($vectors.english[0][1],$vectors.english[1][1])
    $expected=@(foreach ($mnemonic in $mnemonics) { GetBIP39Seed $mnemonic })
    $actual=@($mnemonics | GetBIP39Seed)
    Assert-Equal $actual.Count 2
    Assert-Equal ($actual -join ',') ($expected -join ',')
}
Complete-TestSuite
