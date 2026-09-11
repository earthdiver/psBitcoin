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
    @{Command='Bech32_Encode'; Values=@($a.addresses.P2WPKH.script.Substring(4),$b.addresses.P2WPKH.script.Substring(4));Options=@{hrp='bc';m=$false;v=0}},
    @{Command='Bech32_Decode'; Values=@($a.addresses.P2WPKH.address,$b.addresses.P2WPKH.address)},
    @{Command='GetTweakedWIF'; Values=@($a.wif,$b.wif)},
    @{Command='GetURI'; Values=@($a.addresses.P2PKH.address,$b.addresses.P2PKH.address)},
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
        $values=@($case.Values) + @($case.Values[0])
        $expected=@(foreach ($value in $values) { & $command $value @options })
        $actual=@($values | & $command @options)
        Assert-Equal $actual.Count $expected.Count 'Pipeline must not silently discard earlier items'
        Assert-Equal ($actual -join '|') ($expected -join '|') 'Pipeline must preserve input order'
    }
    Test "Empty pipeline does not invoke $($case.Command)" {
        $options=@{}
        if ($case.Options) { $options=$case.Options }
        Assert-Equal @(@() | & $case.Command @options).Count 0
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
Test 'Empty conversion records do not stop subsequent records' {
    Assert-Equal (@('', '01', '', '0203') | h2i | i2h) '010203'
    Assert-Equal (@('', '00000001', '', '0000001000000011') | b2i | i2h) '010203'
}
Test 'Early descriptor failures do not stop subsequent records' {
    Assert-Equal ((@('invalid','raw(deadbeef)#89f8spxm','bad','raw(deadbeef)#89f8spxm') | descsum_check) -join ',') 'False,True,False,True'
}
Test 'Chained key and address conversions retain all fixture records' {
    # Use mainnet fixtures explicitly: fixtures alternate mainnet and testnet.
    $records=@($core.addresses[0],$core.addresses[2],$core.addresses[4])
    $actual=@($records.private | GetWIF | GetPublicKeyFromWIF | GetAddressP2WPKH)
    Assert-Equal ($actual -join ',') (($records | ForEach-Object { $_.addresses.P2WPKH.address }) -join ',')
}
Test 'Mixed address formats and networks preserve scripts and URI options' {
    $addresses=@($core.addresses[0].addresses.P2PKH,$core.addresses[1].addresses.P2WPKH,$core.addresses[0].addresses.P2TR)
    $actual=@($addresses | ForEach-Object { ConvertAddressToScriptPubKey $_.address })
    Assert-Equal ($actual -join ',') ($addresses.script -join ',')
    $uris=@($addresses | ForEach-Object { $_.address } | GetURI -amount 0.001 -label 'a b')
    Assert-Equal $uris.Count 3
    for ($index=0; $index -lt 3; $index++) {
        Assert-Equal $uris[$index] ('bitcoin:'+$addresses[$index].address+'?amount=0.001&label=a%20b')
    }
}
Test 'All advertised pipeline functions have per-record processing' {
    foreach ($file in @($WalletFile,'BitcoinTransaction.ps1','SeedQR.ps1')) {
        $tokens=$null; $errors=$null
        $source=Get-Content (Join-Path $SourceRoot $file) -Raw -Encoding UTF8
        $ast=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
        Assert-Equal @($errors).Count 0
        foreach ($function in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$true)) {
            if ($function.Name -in @('AssertBitcoinAddress','GetTweak','Base58Address_Decode','ConvertAddressToScriptPubKey')) {
                Assert-True ($null -eq $function.Body.ProcessBlock) $function.Name
                Assert-False ($function.Body.ParamBlock.Extent.Text -match 'ValueFromPipeline') $function.Name
            }
            if ($function.Body.ParamBlock.Extent.Text -match 'ValueFromPipeline\s*=\s*\$True') {
                Assert-True ($null -ne $function.Body.ProcessBlock) "$file / $($function.Name)"
            }
        }
    }
}
Complete-TestSuite
