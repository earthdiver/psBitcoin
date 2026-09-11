param([string]$SourceRoot = (Split-Path -Parent $PSScriptRoot), [string]$WalletFile = 'BitcoinWallet.ps1', [string]$ResultPath = '')
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
. (Join-Path $SourceRoot $WalletFile)
. (Join-Path $SourceRoot 'BitcoinTransaction.ps1')
$core=Read-Fixture 'core.json'
function Reset-Http {
    $script:Requests=[Collections.Generic.List[object]]::new()
    $script:Sleeps=[Collections.Generic.List[int]]::new()
    $script:FailuresRemaining=0
    $script:Response=@()
}
function Invoke-RestMethod {
    param($Uri,$TimeoutSec,$ErrorAction)
    $script:Requests.Add([pscustomobject]@{Uri=$Uri;Timeout=$TimeoutSec;ErrorAction=$ErrorAction})
    if ($script:FailuresRemaining -gt 0) { $script:FailuresRemaining--; throw 'simulated HTTP failure' }
    return $script:Response
}
function Start-Sleep { param([int]$Milliseconds) $script:Sleeps.Add($Milliseconds) }
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
        $script:Response=@(
            [pscustomobject]@{txid='small';vout=0;value=100;status=@{confirmed=$true;block_time=1}},
            [pscustomobject]@{txid='pending';vout=0;value=9999;status=@{confirmed=$false}},
            [pscustomobject]@{txid='new';vout=1;value=200;status=@{confirmed=$true;block_time=3}},
            [pscustomobject]@{txid='old';vout=2;value=200;status=@{confirmed=$true;block_time=2}}
        )
        $utxos=@(GetUTXO $address.ToUpperInvariant())
        Assert-Equal ($utxos.txid -join ',') 'old,new,small'
        Assert-Equal $utxos[0].vout 2
        foreach ($utxo in $utxos) { Assert-Equal $utxo.script $v.addresses.P2WPKH.script }
        $prefix=if ($testnet) {'https://mempool.space/testnet'} else {'https://mempool.space'}
        Assert-Equal $script:Requests[0].Uri "$prefix/api/address/$address/utxo"
    }
    Test "UTXO zero, one, and failed responses testnet=$testnet" {
        Reset-Http; Assert-Equal @(GetUTXO $address).Count 0
        $script:Response=@([pscustomobject]@{txid='one';vout=0;value=1;status=@{confirmed=$true;block_time=1}})
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
    $script:Response=@([pscustomobject]@{txid='one';vout=0;value=1;status=@{confirmed=$true;block_time=1}})
    $addresses=@($core.addresses[0].addresses.P2WPKH.address,$core.addresses[2].addresses.P2WPKH.address)
    $actual=@($addresses | GetUTXO)
    Assert-Equal $actual.Count 2 'One UTXO result for each address'
    Assert-Equal $script:Requests.Count 2
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
Complete-TestSuite
