param([string]$SourceRoot = (Split-Path -Parent $PSScriptRoot), [string]$WalletFile = 'BitcoinWallet.ps1', [string]$ResultPath = '')
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
. (Join-Path $SourceRoot $WalletFile)
. (Join-Path $SourceRoot 'BitcoinTransaction.ps1')
. (Join-Path $PSScriptRoot 'TransactionSupport.ps1')
$core=Read-Fixture 'core.json'
function Reset-Http {
    $script:Requests=[Collections.Generic.List[object]]::new()
    $script:Sleeps=[Collections.Generic.List[int]]::new()
    $script:FailuresRemaining=0
    $script:Response=@()
    $script:Previous=@{}
    $script:AddressResponses=@{}
}
function Invoke-RestMethod {
    param($Uri,$TimeoutSec,$ErrorAction)
    $script:Requests.Add([pscustomobject]@{Uri=$Uri;Timeout=$TimeoutSec;ErrorAction=$ErrorAction})
    if ($script:FailuresRemaining -gt 0) { $script:FailuresRemaining--; throw 'simulated HTTP failure' }
    if ($Uri -match '/tx/([0-9a-f]{64})/hex$') {
        if (-not $script:Previous.ContainsKey($Matches[1])) { throw 'previous transaction unavailable' }
        return $script:Previous[$Matches[1]]
    }
    if ($script:AddressResponses.ContainsKey($Uri)) { return $script:AddressResponses[$Uri] }
    return $script:Response
}
function Start-Sleep { param([int]$Milliseconds) $script:Sleeps.Add($Milliseconds) }
# Synthetic funding transactions use independent hashing, never the production parser.
function New-TestUTXO($Script,[UInt64]$Value,[int]$Index=0,[int]$Time=1,[switch]$Witness) {
    $body='01'+('01'*32)+'0000000000ffffffff'+('{0:x2}' -f ($Index+1))
    for ($n=0;$n -lt $Index;$n++) { $body+='000000000000000000' }
    $body += [TestCrypto]::Hex([BitConverter]::GetBytes($Value))+('{0:x2}' -f ($Script.Length/2))+$Script
    $stripped='02000000'+$body+'00000000'
    $hash=[TestCrypto]::Bytes([TestCrypto]::DoubleSha($stripped)); [Array]::Reverse($hash)
    $id=[TestCrypto]::Hex($hash)
    $script:Previous[$id]=if ($Witness) {'020000000001'+$body+'0101aa00000000'} else {$stripped}
    return [pscustomobject]@{txid=$id;vout=$Index;value=$Value;status=@{confirmed=$true;block_time=$Time}}
}
foreach ($failures in @(0,1,2,3)) {
    Test "Retry succeeds after $failures failures" {
        Reset-Http; $script:FailuresRemaining=$failures; $script:Response=@('response')
        $actual=Invoke-RestMethodWithRetry 'https://example.invalid/test' -RetryCount 3 -TimeoutSec 7
        Assert-True $actual.Succeeded
        Assert-Equal $actual.Value 'response'
        Assert-Equal $script:Requests.Count ($failures+1)
        Assert-Equal $script:Sleeps.Count $failures
        foreach ($request in $script:Requests) { Assert-Equal $request.Timeout 7; Assert-Equal $request.ErrorAction 'Stop' }
        foreach ($sleep in $script:Sleeps) { Assert-Equal $sleep 500 }
    }
}
foreach ($retry in @(0,1,5)) {
    Test "Retry exhaustion limit $retry" {
        Reset-Http; $script:FailuresRemaining=99
        $actual=Invoke-RestMethodWithRetry 'https://example.invalid/test' -RetryCount $retry
        Assert-False $actual.Succeeded
        Assert-Equal $null $actual.Value
        Assert-Equal $script:Requests.Count ($retry+1)
        Assert-Equal $script:Sleeps.Count $retry
    }
}
Test 'Empty successful response is not a transport failure' {
    Reset-Http
    $actual=Invoke-RestMethodWithRetry 'https://example.invalid/test'
    Assert-True $actual.Succeeded
    Assert-Equal $script:Requests.Count 1
}
foreach ($testnet in @($false,$true)) {
    $v=$core.addresses[[int]$testnet]
    $address=$v.addresses.P2WPKH.address
    Test "UTXO filters unconfirmed, sorts, and supplies scripts testnet=$testnet" {
        Reset-Http
        $small=New-TestUTXO $v.addresses.P2WPKH.script 100
        $new=New-TestUTXO $v.addresses.P2WPKH.script 200 1 3 -Witness
        $old=New-TestUTXO $v.addresses.P2WPKH.script 200 2 2
        $script:Response=@($small,[pscustomobject]@{txid='pending';status=@{confirmed=$false}},$new,$old)
        $utxos=@(GetUTXO $address.ToUpperInvariant())
        Assert-Equal ($utxos.txid -join ',') (@($old.txid,$new.txid,$small.txid) -join ',')
        Assert-Equal $utxos[0].vout 2
        foreach ($utxo in $utxos) { Assert-Equal $utxo.script $v.addresses.P2WPKH.script }
        Assert-Equal $script:Requests.Count 4
        $prefix=if ($testnet) {'https://mempool.space/testnet'} else {'https://mempool.space'}
        Assert-Equal $script:Requests[0].Uri "$prefix/api/address/$address/utxo"
    }
    Test "UTXO zero, one, and failed responses testnet=$testnet" {
        Reset-Http; Assert-Equal @(GetUTXO $address).Count 0
        $script:Response=@(New-TestUTXO $v.addresses.P2WPKH.script 1)
        Assert-Equal @(GetUTXO $address).Count 1
        $script:FailuresRemaining=99
        Assert-Throws { GetUTXO $address } 'failed to get utxo'
    }
}
Test 'Invalid address is rejected before HTTP' {
    Reset-Http
    Assert-Throws { GetUTXO 'invalid' } 'address'
    Assert-Throws { GetBalance 'invalid' } 'address'
    $root=[HDWallet]::new('000102030405060708090a0b0c0d0e0f')
    Assert-Throws { GetBalance $root.GetExtendedPrivateKey() } 'private keys'
    Assert-Equal $script:Requests.Count 0
}
Test 'Balance primary response and fallback fields' {
    Reset-Http
    $addr=$core.addresses[0].addresses.P2PKH.address
    $script:Response=@{}; $script:Response[$addr]=[pscustomobject]@{final_balance=123;n_tx=2;total_received=150}
    Assert-Equal (GetBalance $addr).final_balance 123
    Assert-Equal $script:Requests.Count 1
    Assert-Equal $script:Requests[0].Uri "https://blockchain.info/balance?active=$addr"
    Reset-Http; $script:FailuresRemaining=1
    $script:Response=[pscustomobject]@{final_balance=123;n_tx=2;total_received=150;extra='ignored'}
    $actual=GetBalance $addr
    Assert-Equal $actual.final_balance 123
    Assert-Equal ($actual.PSObject.Properties.Name -join ',') 'final_balance,n_tx,total_received'
    Assert-Equal $script:Requests[1].Uri "https://api.blockcypher.com/v1/btc/main/addrs/$addr/balance"
    Reset-Http; $script:FailuresRemaining=2
    Assert-Throws { GetBalance $addr } 'failed to get the balance'
    Assert-Equal $script:Requests.Count 2
}
Test 'GetUTXO pipeline handles both addresses' {
    Reset-Http
    $addresses=@($core.addresses[0].addresses.P2WPKH.address,$core.addresses[3].addresses.P2WPKH.address)
    $uris=@("https://mempool.space/api/address/$($addresses[0])/utxo","https://mempool.space/testnet/api/address/$($addresses[1])/utxo")
    $script:AddressResponses[$uris[0]]=@(New-TestUTXO $core.addresses[0].addresses.P2WPKH.script 1)
    $script:AddressResponses[$uris[1]]=@(New-TestUTXO $core.addresses[3].addresses.P2WPKH.script 1)
    $actual=@($addresses | GetUTXO)
    Assert-Equal $actual.Count 2
    Assert-Equal $script:Requests.Count 4
    Assert-Equal $actual[0].script $core.addresses[0].addresses.P2WPKH.script
    Assert-Equal $actual[1].script $core.addresses[3].addresses.P2WPKH.script
    Assert-Equal $script:Requests[0].Uri $uris[0]
    Assert-Equal $script:Requests[2].Uri $uris[1]
}
Test 'GetBalance pipeline handles both addresses' {
    Reset-Http
    $addresses=@($core.addresses[0].addresses.P2PKH.address,$core.addresses[2].addresses.P2PKH.address)
    $script:Response=@{}
    foreach ($addr in $addresses) { $script:Response[$addr]=[pscustomobject]@{final_balance=1} }
    $actual=@($addresses | GetBalance)
    Assert-Equal $actual.Count 2 'One balance result for each address'
    Assert-Equal $script:Requests.Count 2
}
Test 'Empty network pipelines do not issue requests' {
    Reset-Http
    Assert-Equal @(@() | GetUTXO).Count 0
    Assert-Equal @(@() | GetBalance).Count 0
    Assert-Equal $script:Requests.Count 0
}
foreach ($testnet in @($false,$true)) {
    $v=$core.addresses[[int]$testnet]
    foreach ($kind in @('P2PKH','P2SH','P2WPKH','P2SH-P2WPKH','P2WSH','P2SH-P2WSH','P2TR','P2TR-SP')) {
        $source=$v.addresses.$kind
        foreach ($delta in @(-1,1)) {
            Test "Reject indexed amount delta=$delta $kind testnet=$testnet" {
                Reset-Http
                $entry=New-TestUTXO $source.script 100000 -Witness
                $entry.value += $delta
                $script:Response=@($entry)
                Assert-Throws { GetUTXO $source.address } 'amount mismatch'
            }
        }
    }
    foreach ($fault in @('duplicate','range','script','hash','missing','malformed','negative','fraction','overflow')) {
        Test "Reject invalid prevout $fault testnet=$testnet" {
            Reset-Http
            $entry=New-TestUTXO $v.addresses.P2PKH.script 100000
            $script:Response=@($entry)
            switch ($fault) {
                duplicate { $script:Response=@($entry,$entry); $pattern='duplicate' }
                range { $entry.vout=1; $pattern='out of range' }
                script { $entry=New-TestUTXO '51' 100000; $script:Response=@($entry); $pattern='script mismatch' }
                hash { $script:Previous[$entry.txid]=$script:Previous[$entry.txid] -replace '^02','03'; $pattern='txid mismatch' }
                missing { $script:Previous=@{}; $pattern='failed to get previous' }
                malformed { $script:Previous[$entry.txid]='zz'; $pattern='invalid previous' }
                negative { $entry.value=-1; $pattern='metadata' }
                fraction { $entry.vout=0.5; $pattern='metadata' }
                overflow { $entry.value='2100000000000001'; $pattern='metadata' }
            }
            Assert-Throws { GetUTXO $v.addresses.P2PKH.address } $pattern
        }
    }
}
foreach ($testnet in @($false,$true)) {
    $v=$core.addresses[[int]$testnet]
    foreach ($kind in @('P2PKH','P2SH','P2WPKH','P2TR','Nulldata')) {
        Test "Builder rejects forged prevout before signing $kind testnet=$testnet" {
            function EcdsaSig { $script:SignCalls++; throw 'unexpected signing' }
            function SchnorrSig { $script:SignCalls++; throw 'unexpected signing' }
            $script:SignCalls=0
            Reset-Http
            $source=if ($kind -eq 'Nulldata') {$v.addresses.P2WPKH} else {$v.addresses.$kind}
            $entry=New-TestUTXO $source.script 1000000
            $entry.value=61000
            $script:Response=@($entry)
            $arguments=@{wif=$v.wif;addressFrom=$source.address;fee=1000}
            if ($kind -eq 'Nulldata') {
                $command='NulldataTX'; $arguments.text='hello'
            } else {
                $command=if ($kind -in @('P2PKH','P2SH')) {'RawTXfromLegacyAddress'} elseif ($kind -eq 'P2TR') {'RawTXfromTaprootAddress'} else {'RawTXfromSegwitAddress'}
                $arguments.addressTo=$v.addresses.P2PKH.address; $arguments.amount=60000
            }
            Assert-Throws { & $command @arguments } 'amount mismatch'
            Assert-Equal $script:SignCalls 0
        }
    }
}
Test 'Previous transaction parser rejects truncated, trailing and noncanonical data' {
    Reset-Http
    $entry=New-TestUTXO '51' 100000
    $raw=$script:Previous[$entry.txid]
    for ($length=0;$length -lt $raw.Length;$length+=2) {
        Assert-Throws { ReadPreviousTransaction $raw.Substring(0,$length) }
    }
    Assert-Throws { ReadPreviousTransaction ($raw+'00') } 'trailing'
    Assert-Throws { ReadPreviousTransaction ($raw.Substring(0,8)+'fd0100'+$raw.Substring(10)) } 'noncanonical'
    Assert-Throws { ReadPreviousTransaction ($raw.Substring(0,8)+'ff0000000001000000'+$raw.Substring(10)) } 'size'
    Assert-Throws { ReadPreviousTransaction ('020000000002'+$raw.Substring(8)) } 'witness flag'
    Assert-Throws { ReadPreviousTransaction ('020000000001'+$raw.Substring(8,$raw.Length-16)+'00'+'00000000') } 'superfluous'
}
Test 'Previous transaction amount enforces MAX_MONEY including unsigned overflow' {
    Reset-Http
    foreach ($value in @([UInt64]2100000000000001,[UInt64]::MaxValue)) {
        $entry=New-TestUTXO '51' $value
        Assert-Throws { ReadPreviousTransaction $script:Previous[$entry.txid] } 'MAX_MONEY'
    }
}
Test 'Shared previous transaction is fetched once' {
    Reset-Http
    $source=$core.addresses[0].addresses.P2PKH
    $entry=New-TestUTXO $source.script 100000
    $raw=$script:Previous[$entry.txid]
    # Replace the single output count with two and append a duplicate output.
    $raw=$raw.Substring(0,92)+'02'+$raw.Substring(94,$raw.Length-102)+$raw.Substring(94)
    $hash=[TestCrypto]::Bytes([TestCrypto]::DoubleSha($raw)); [Array]::Reverse($hash)
    $entry.txid=[TestCrypto]::Hex($hash)
    $script:Previous[$entry.txid]=$raw
    $second=$entry.PSObject.Copy(); $second.vout=1
    $script:Response=@($entry,$second)
    Assert-Equal @(GetUTXO $source.address).Count 2
    Assert-Equal $script:Requests.Count 2
    $second.value=1
    $received=[Collections.Generic.List[object]]::new()
    Assert-Throws { GetUTXO $source.address | ForEach-Object { $received.Add($_) } } 'amount mismatch'
    Assert-Equal $received.Count 0
}
Complete-TestSuite
