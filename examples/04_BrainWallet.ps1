### DO NOT USE THIS CODE TO CREATE A PRIVATE KEY. THIS IS FOR INFORMATIONAL PURPOSES ONLY. ###
echo "<<< Classic Brain Wallet >>>"
$BWPassphrase = "I am a cat"                      # passphrase
$bytes = [Text.Encoding]::UTF8.GetBytes( $BWPassphrase )
$NumOfHashings = 1                                # the number of iterations of SHA256
$hash = $bytes
$SHA256 = New-Object Security.Cryptography.SHA256CryptoServiceProvider
0..($NumOfHashings - 1) | % { $hash = $SHA256.ComputeHash( $hash ) }

$privatekey = i2h $hash
$wif        = GetWIF $privatekey
$publickey  = GetPublicKey $privatekey
$pubkeyHash = Hash160 $publickey
$address    = GetAddressP2PKH $publickey

echo "Passphrase        : $bwPassphrase"
echo "Private Key (Hex) : $privatekey"
echo "WIF Private Key   : $wif"
echo "Public Key        : $publickey"
echo "Public Key Hash   : $pubkeyHash"
echo "Compressed Address: $address"
