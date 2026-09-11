param([string]$SourceRoot = (Split-Path -Parent $PSScriptRoot), [string]$WalletFile = 'BitcoinWallet.ps1', [string]$ResultPath = '')
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
. (Join-Path $SourceRoot $WalletFile)
. (Join-Path $SourceRoot 'BitcoinTransaction.ps1')
. (Join-Path $PSScriptRoot 'TransactionSupport.ps1')
$core=Read-Fixture 'core.json'
function GetUTXO {
    param($Address)
    $script:FetchCount++
    Assert-Equal $Address $script:ExpectedSource
    return $script:Utxos
}
function Set-BuilderUTXO($Address,$Script,[UInt64[]]$Values) {
    $script:FetchCount=0; $script:ExpectedSource=$Address
    $script:Utxos=@(for ($i=0;$i -lt $Values.Count;$i++) {
        [pscustomobject]@{txid=('{0:x2}' -f ($i+1))*32;vout=$i;value=$Values[$i];script=$Script}
    })
}
function Assert-BuilderSignatures($Parsed,$Kind,$Vector) {
    $tx=ConvertTo-TestTXS $Parsed
    for ($i=0;$i -lt $Parsed.Inputs.Count;$i++) {
        if ($Kind -in @('P2PKH','P2SH')) {
            $stack=$Parsed.Inputs[$i].Script
            $sigLength=[Convert]::ToInt32($stack.Substring(0,2),16)
            $sig=$stack.Substring(2,$sigLength*2)
            $rest=$stack.Substring(2+$sigLength*2)
            $redeem=if ($Kind -eq 'P2PKH') {$Vector.public} else {'21'+$Vector.public+'ac'}
            Assert-Equal $rest (('{0:x2}' -f ($redeem.Length/2))+$redeem)
            $scriptCode=if ($Kind -eq 'P2PKH') {$Vector.addresses.P2PKH.script} else {$redeem}
            $signInputs=[TXin[]]@(for ($j=0;$j -lt $Parsed.Inputs.Count;$j++) {
                $inputScript=if ($i -eq $j) {$scriptCode} else {''}
                [TXin]::new($Parsed.Inputs[$j].Txid,$Parsed.Inputs[$j].Index,$inputScript,$Parsed.Inputs[$j].Sequence)
            })
            $pre=[TX]::new($Parsed.Version,$signInputs,$tx.txouts,$Parsed.Locktime).ToString()+'01000000'
            $digest=[TestCrypto]::DoubleSha($pre)
            Assert-Equal $sig.Substring($sig.Length-2) '01'
            Assert-True ([TestCrypto]::VerifyEcdsa($digest,$sig.Substring(0,$sig.Length-2),$Vector.public))
        } elseif ($Kind -in @('P2TR','P2TR-SP')) {
            Assert-Equal $Parsed.Inputs[$i].Script ''
            Assert-Equal $Parsed.Stacks[$i].Items.Count $(if ($Kind -eq 'P2TR-SP') {3} else {1})
            $sig=$Parsed.Stacks[$i].Items[0]
            $scripts=[string[]]@($script:Utxos | Select-Object -First $Parsed.Inputs.Count | ForEach-Object {$_.script})
            $values=[UInt64[]]@($script:Utxos | Select-Object -First $Parsed.Inputs.Count | ForEach-Object {$_.value})
            if ($Kind -eq 'P2TR-SP') {
                Assert-Equal $Parsed.Stacks[$i].Items[1] $Vector.tapScript
                Assert-Equal $Parsed.Stacks[$i].Items[2] $Vector.controlBlock
                $leaf=[TestCrypto]::Tagged('TapLeaf',('c022'+$Vector.tapScript))
                $pre='00'+[TaprootMsg]::new($tx,$i,$scripts,$values,0,1,'',$leaf).ToString()
                $pub=$Vector.public.Substring(2)
            } else {
                $pre='00'+[TaprootMsg]::new($tx,$i,$scripts,$values).ToString()
                $pub=$Vector.addresses.P2TR.script.Substring(4)
            }
            Assert-True ([TestCrypto]::VerifySchnorr([TestCrypto]::Tagged('TapSighash',$pre),$sig,$pub))
        } else {
            $sig=$Parsed.Stacks[$i].Items[0]
            $isScript=$Kind -in @('P2WSH','P2SH-P2WSH')
            $redeem=if ($isScript) {'21'+$Vector.public+'ac'} else {$Vector.public}
            Assert-Equal $Parsed.Stacks[$i].Items.Count 2
            Assert-Equal $Parsed.Stacks[$i].Items[1] $redeem
            $scriptCode=if ($isScript) {$redeem} else {$Vector.addresses.P2PKH.script}
            $expectedScript=if ($Kind -eq 'P2SH-P2WPKH') {'16'+$Vector.addresses.P2WPKH.script} elseif ($Kind -eq 'P2SH-P2WSH') {'22'+$Vector.addresses.P2WSH.script} else {''}
            Assert-Equal $Parsed.Inputs[$i].Script $expectedScript
            $pre=[SegwitMsg]::new($tx,$i,(ConvertTo-CompactSizeHex $scriptCode),$script:Utxos[$i].value,1).ToString()
            Assert-Equal $sig.Substring($sig.Length-2) '01'
            Assert-True ([TestCrypto]::VerifyEcdsa([TestCrypto]::DoubleSha($pre),$sig.Substring(0,$sig.Length-2),$Vector.public))
        }
    }
}
foreach ($testnet in @($false,$true)) {
    $v=$core.addresses[[int]$testnet]
    foreach ($kind in @('P2PKH','P2SH','P2WPKH','P2SH-P2WPKH','P2WSH','P2SH-P2WSH','P2TR','P2TR-SP')) {
        $source=$v.addresses.$kind
        $command=if ($kind -in @('P2PKH','P2SH')) {'RawTXfromLegacyAddress'} elseif ($kind -in @('P2TR','P2TR-SP')) {'RawTXfromTaprootAddress'} else {'RawTXfromSegwitAddress'}
        $arguments=@{wif=$v.wif;addressFrom=$source.address;addressTo=$v.addresses.P2PKH.address;amount=60000;fee=1000}
        if ($kind -in @('P2WSH','P2SH-P2WSH')) { $arguments.witnessScript='single' }
        if ($kind -eq 'P2TR-SP') { $arguments.tapScript='single' }
        if ($kind -eq 'P2SH') { $arguments.redeemScript='21'+$v.public+'ac' }
        Test "Generate and independently verify $kind testnet=$testnet two inputs, change, memo, locktime" {
            Set-BuilderUTXO $source.address $source.script @(50000,30000,10000)
            $raw=& $command @arguments -memo 'hello' -lockTime 500
            Assert-True ($raw -is [string])
            $parsed=Read-TestTransaction $raw
            Assert-Equal $script:FetchCount 1
            Assert-Equal $parsed.Version 2; Assert-Equal $parsed.Locktime 500
            Assert-Equal $parsed.Inputs.Count 2; Assert-Equal $parsed.Outputs.Count 3
            Assert-Equal $parsed.Inputs[0].Txid ('01'*32); Assert-Equal $parsed.Inputs[1].Index 1
            Assert-Equal $parsed.Inputs[0].Sequence 4294967293
            Assert-Equal $parsed.Outputs[0].Value 60000
            Assert-Equal $parsed.Outputs[0].Script $v.addresses.P2PKH.script
            Assert-Equal $parsed.Outputs[1].Value 19000
            Assert-Equal $parsed.Outputs[1].Script $source.script
            Assert-Equal $parsed.Outputs[2].Value 0; Assert-Equal $parsed.Outputs[2].Script '6a0568656c6c6f'
            Assert-BuilderSignatures $parsed $kind $v
        }
        Test "Builder rejects insufficient and empty UTXOs $kind testnet=$testnet" {
            Set-BuilderUTXO $source.address $source.script @()
            Assert-Throws { & $command @arguments } 'balance'
            Set-BuilderUTXO $source.address $source.script @(50000)
            Assert-Throws { & $command @arguments } 'balance'
        }
        Test "Builder exact funding and dust-change opt-in $kind testnet=$testnet" {
            Set-BuilderUTXO $source.address $source.script @(61000)
            $parsed=Read-TestTransaction (& $command @arguments)
            Assert-Equal $parsed.Outputs.Count 1
            Set-BuilderUTXO $source.address $source.script @(61100)
            Assert-Throws { & $command @arguments } 'dust'
            $parsed=Read-TestTransaction (& $command @arguments -AllowDustToFee)
            Assert-Equal $parsed.Outputs.Count 1
            Assert-Equal $parsed.Outputs[0].Value 60000
        }
        Test "Builder invalid destination, wrong key and memo $kind testnet=$testnet" {
            Set-BuilderUTXO $source.address $source.script @(100000)
            $bad=$arguments.Clone(); $bad.addressTo='invalid'
            Assert-Throws { & $command @bad }
            $bad=$arguments.Clone(); $bad.wif=$core.addresses[2+[int]$testnet].wif
            # The automatic single-key P2SH path validates the key. Arbitrary custom scripts do not.
            if ($kind -eq 'P2SH') { $bad.redeemScript='single' }
            Assert-Throws { & $command @bad } $(if ($kind -eq 'P2TR-SP') {'tapScript'} else {'does not match'})
            Assert-Equal $script:FetchCount $(if ($kind -eq 'P2TR-SP') {1} else {0})
            Assert-Throws { & $command @arguments -memo ('a'*41) } 'memo'
            $bad=$arguments.Clone(); $bad.amount=1
            Assert-Throws { & $command @bad } 'dust'
        }
    }
    Test "Nulldata funding and script output testnet=$testnet" {
        $source=$v.addresses.P2WPKH
        Set-BuilderUTXO $source.address $source.script @(2000)
        $parsed=Read-TestTransaction (NulldataTX $v.wif $source.address 'hello' 1000 -lockTime 500)
        Assert-Equal $parsed.Outputs[0].Value 0
        Assert-Equal $parsed.Outputs[0].Script '6a0568656c6c6f'
        Assert-Equal $parsed.Outputs[1].Value 1000
        Assert-Equal $parsed.Locktime 500
        Assert-BuilderSignatures $parsed 'P2WPKH' $v
        Set-BuilderUTXO $source.address $source.script @(949)
        Assert-Throws { NulldataTX $v.wif $source.address 'hello' 1000 } 'balance'
        Set-BuilderUTXO $source.address $source.script @(950)
        $parsed=Read-TestTransaction (NulldataTX $v.wif $source.address 'hello' 1000)
        Assert-Equal $parsed.Outputs.Count 1
        Assert-Throws { NulldataTX $v.wif $source.address ('a'*41) 1000 } 'text'
        Assert-Throws { NulldataTX $v.wif $v.addresses.P2TR.address 'hello' 1000 } 'Taproot'
    }
}
Test 'CLTV timestamp boundaries and offset equivalence' {
    $pub=$core.addresses[0].public
    $utc=@(CLTVScript '2038-01-19T03:14:08Z' $pub)
    $offset=@(CLTVScript '2038-01-19T12:14:08+09:00' $pub)
    Assert-Equal ($utc -join '|') ($offset -join '|')
    Assert-True ($utc[-1].EndsWith('050000008000b17521'+$pub+'ac'))
    Assert-Throws { CLTVScript '2038-01-19T03:14:08' $pub } 'UTC offset'
    Assert-Throws { CLTVScript '1970-01-01T00:00:00Z' $pub } 'range'
    Assert-Throws { CLTVScript '2106-02-07T06:28:16Z' $pub } 'range'
    Assert-Throws { CLTVScript 'not-a-dateZ' $pub } 'datetime'
}
Complete-TestSuite
