# Verifying the payment address derivation of Conkite satscard
# Note: Python and the 'cktap' python library need to be installed.
$result= python -c @'
from cktap.transport import find_first
from cktap.utils     import *
card = find_first()
n = pick_nonce()
r = card.send('derive',nonce=n)
a = card.get_address()
print(r['chain_code'].hex())
print(r['master_pubkey'].hex())
print(a)
exit()
'@
$HMACSHA512 = New-Object Security.Cryptography.HMACSHA512
$version = "0488b21e"
$depth        = "00"
$pFingerprint = "00000000" 
$childnumber  = "00000000"
$chaincode    = $result[0]
$publickey    = $result[1]
$serialized   = $version + $depth + $pFingerprint + $childnumber + $chaincode + $publickey
$xpub = Base58Check_Encode $serialized
($w=[HDWallet]::new()).ImportExtendedKey($xpub,'m')
Write-Host "Chain Code        : $($result[0])"
Write-Host "Master PublicKey  : $($result[1])"
Write-Host "PublicKey         : $($w.Derive(0,$false).PublicKey)"
Write-Host "Address (expected): $($result[2])"
Write-Host "Address (derived) : $($w.Derive(0,$false).GetAddressP2WPKH())"
