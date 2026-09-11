param([string]$SourceRoot = (Split-Path -Parent $PSScriptRoot), [string]$WalletFile = 'BitcoinWallet.ps1', [string]$ResultPath = '')
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
. (Join-Path $SourceRoot $WalletFile)
. (Join-Path $SourceRoot 'BitcoinTransaction.ps1')
. (Join-Path $PSScriptRoot 'TransactionSupport.ps1')
$core=Read-Fixture 'core.json'
$fixture=$core.transaction
$inputs=[TXin[]]@($fixture.inputs | ForEach-Object { [TXin]::new($_.txid,$_.index,'',$_.sequence) })
$outputs=[TXout[]]@($fixture.outputs | ForEach-Object { [TXout]::new($_.value,$_.script) })
$stacks=[Witness[]]@([Witness]::new(),[Witness]::new())
$tx=[TXS]::new($fixture.version,0,1,$inputs,$outputs,$stacks,$fixture.locktime)
$scripts=[string[]]@($fixture.inputs | ForEach-Object {$_.script})
$values=[UInt64[]]@($fixture.inputs | ForEach-Object {$_.value})
Test 'TXin exact field order, endianness and RBF default' {
    Assert-Equal ([TXin]::new(('01'*32),7,'51')).ToString() (('01'*32)+'070000000151fdffffff')
    Assert-Equal ([TXin]::new(('01'*32),7,'',4294967295)).ToString() (('01'*32)+'0700000000ffffffff')
}
Test 'TXout and witness byte serialization' {
    Assert-Equal ([TXout]::new(1000,'51')).ToString() 'e8030000000000000151'
    Assert-Equal ([Witness]::new()).ToString() '00'
    Assert-Equal ([Witness]::new([string[]]@('','ABCD','51'))).ToString() '030002abcd0151'
    Assert-Equal ([DER]::new('01','02')).ToString() '3006020101020102'
}
Test 'Legacy and witness serialization independently parsed' {
    $legacy=Read-TestTransaction ([TX]::new(2,$inputs,$outputs,500)).ToString()
    Assert-False $legacy.Witness
    Assert-Equal $legacy.Version 2; Assert-Equal $legacy.Locktime 500
    Assert-Equal $legacy.Inputs.Count 2; Assert-Equal $legacy.Outputs.Count 2
    Assert-Equal $legacy.Inputs[0].Txid $fixture.inputs[0].txid
    Assert-Equal $legacy.Inputs[1].Sequence $fixture.inputs[1].sequence
    Assert-Equal $legacy.Outputs[1].Value $fixture.outputs[1].value
    $nonempty=[Witness[]]@([Witness]::new([string[]]@('51')),[Witness]::new())
    $segwit=Read-TestTransaction ([TXS]::new(2,0,1,$inputs,$outputs,$nonempty,500)).ToString()
    Assert-True $segwit.Witness
    Assert-Equal $segwit.Stacks.Count 2
    Assert-Equal $segwit.Stacks[0].Items[0] '51'
    Assert-Equal $segwit.Stacks[1].Items.Count 0
}
foreach ($v in $core.sighashes) {
    Test "Independent sighash $($v.kind) input=$($v.index) flag=$($v.flag) ext=$($v.extension) annex=$($v.annex)" {
        if ($v.kind -eq 'segwit') {
            $actual=[SegwitMsg]::new($tx,$v.index,$v.scriptCode,$values[$v.index],$v.flag).ToString()
            Assert-Equal $actual $v.preimage
            Assert-Equal (Hash256 $actual) $v.digest
        } else {
            $actual=[TaprootMsg]::new($tx,$v.index,$scripts,$values,$v.flag,$v.extension,$v.annex,$v.leaf).ToString()
            Assert-Equal $actual $v.preimage
            Assert-Equal (HashTR 'TapSighash' ('00'+$actual)) $v.digest
        }
    }
}
$n=0
foreach ($v in (Read-Fixture 'bip143.json')) {
    Test "BIP143 official preimage $n" {
        $parsed=Read-TestTransaction $v.raw
        $official=ConvertTo-TestTXS $parsed
        # Decode the independent published preimage to identify the signed input.
        $stream=[IO.MemoryStream]::new([TestCrypto]::Bytes($v.preimage))
        $reader=[IO.BinaryReader]::new($stream)
        try {
            $stream.Position=68
            $outpoint=Read-TestHex $reader 36
            $code=Read-TestField $reader
            $value=$reader.ReadUInt64()
            $stream.Position=$stream.Length-4
            $flag=$reader.ReadUInt32()
            $index=-1
            for ($i=0;$i -lt $official.txins.Count;$i++) {
                if (($official.txins[$i].txid+$official.txins[$i].index) -ceq $outpoint) { $index=$i; break }
            }
            Assert-True ($index -ge 0)
            $actual=[SegwitMsg]::new($official,$index,(ConvertTo-CompactSizeHex $code),$value,$flag).ToString()
            Assert-Equal $actual $v.preimage
            Assert-Equal (Hash256 $actual) $v.hash
        } finally { $reader.Dispose(); $stream.Dispose() }
    }
    $n++
}
foreach ($group in (Read-Fixture 'bip341-wallet.json').keyPathSpending) {
    $official=ConvertTo-TestTXS (Read-TestTransaction $group.given.rawUnsignedTx)
    $officialScripts=[string[]]@($group.given.utxosSpent | ForEach-Object {$_.scriptPubKey})
    $officialValues=[UInt64[]]@($group.given.utxosSpent | ForEach-Object {$_.amountSats})
    foreach ($v in $group.inputSpending) {
        Test "BIP341 official input=$($v.given.txinIndex) flag=$($v.given.hashType)" {
            $actual='00'+[TaprootMsg]::new($official,$v.given.txinIndex,$officialScripts,$officialValues,$v.given.hashType).ToString()
            Assert-Equal $actual $v.intermediary.sigMsg
            Assert-Equal (HashTR 'TapSighash' $actual) $v.intermediary.sigHash
        }
    }
}
Test 'Malformed transaction data and structures are rejected' {
    Assert-Throws { [TXin]::new('00',0) } 'txid'
    Assert-Throws { [TXin]::new(('00'*32),0,'gg') } 'scriptSig'
    Assert-Throws { [TXout]::new(1,'a') } 'scriptPubKey'
    Assert-Throws { [TXout]::new(2100000000000001,'51') } 'MAX_MONEY'
    Assert-Throws { [Witness]::new([string[]]@('gg')) } 'witness'
    Assert-Throws { [TX]::new([TXin[]]@(),$outputs) } 'input'
    Assert-Throws { [TX]::new($inputs,[TXout[]]@()) } 'output'
    Assert-Throws { [TX]::new([TXin[]]@($null),$outputs) } 'null'
    Assert-Throws { [TXS]::new(2,1,1,$inputs,$outputs,$stacks,0) } 'marker'
    Assert-Throws { [TXS]::new(2,0,0,$inputs,$outputs,$stacks,0) } 'flag'
    Assert-Throws { [TXS]::new($inputs,$outputs,[Witness[]]@([Witness]::new())) } 'count'
    Assert-Throws { $tx.ToString() } 'empty'
    Assert-Throws { [TX]::new($inputs,[TXout[]]@([TXout]::new(2100000000000000,'51'),[TXout]::new(1,'51'))) } 'total'
}
foreach ($flag in @(4,0x80,0xff)) {
    Test "Reject sighash flag $flag" {
        Assert-Throws { [SegwitMsg]::new($tx,0,'0151',1,$flag) } 'sighash'
        Assert-Throws { [TaprootMsg]::new($tx,0,$scripts,$values,$flag) } 'sighash'
    }
}
Test 'Sighash index, data and extensions are validated' {
    Assert-Throws { [SegwitMsg]::new($tx,2,'0151',1) } 'ntx'
    Assert-Throws { [TaprootMsg]::new($tx,2,$scripts,$values) } 'ntx'
    Assert-Throws { [TaprootMsg]::new($tx,0,[string[]]@('51'),$values) } 'entry'
    Assert-Throws { [TaprootMsg]::new($tx,0,$scripts,[UInt64[]]@(1)) } 'entry'
    Assert-Throws { [TaprootMsg]::new($tx,0,$scripts,$values,0,2,'','') } 'ext_flag'
    Assert-Throws { [TaprootMsg]::new($tx,0,$scripts,$values,0,1,'','') } 'tapleaf_hash'
    Assert-Throws { [TaprootMsg]::new($tx,0,$scripts,$values,0,0,'',('11'*32)) } 'tapleaf_hash'
    Assert-Throws { [TaprootMsg]::new($tx,0,$scripts,$values,0,0,'5100','') } 'annex'
    $oneOutput=[TXS]::new($inputs,[TXout[]]@($outputs[0]))
    Assert-Throws { [TaprootMsg]::new($oneOutput,1,$scripts,$values,3) } 'txouts'
    Assert-Equal ([SegwitMsg]::new($oneOutput,1,'0151',1,3)).hashOutputs ('00'*32)
}
foreach ($case in @(@('76a914',546),@('a914',540),@('0014',294),@('0020',330),@('5120',330),@('6002',330))) {
    Test "Dust policy boundary $($case[0])" {
        Assert-Equal (GetDustThreshold $case[0]) $case[1]
        Assert-Throws { AssertPaymentAmount ($case[1]-1) 0 $case[0] } 'dust'
        AssertPaymentAmount $case[1] 0 $case[0]
        Assert-Throws { AssertPaymentAmount 2100000000000000 1 $case[0] } 'MAX_MONEY'
    }
}
Complete-TestSuite
