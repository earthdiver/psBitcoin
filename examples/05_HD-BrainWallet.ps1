echo "<<< HD Brain Wallet >>>"
$BWPassphrase = "I am a _c_a_t_"                                 # passphrase

$SHA256  = New-Object Security.Cryptography.SHA256CryptoServiceProvider
$bytes = [Text.Encoding]::UTF8.GetBytes( $BWPassphrase * 2 )     # repeat the passphrase twice
$NumOfHashings = 100000                                          # the number of iterations of SHA256
$hash = $bytes
0..($NumOfHashings - 1) | % { $hash = $SHA256.ComputeHash( $hash ) }

$entropy    = $hash[0..15]
$entropy_b  = i2b $entropy
$entropy_h  = i2h $entropy

$mnemonic   = GetMnemonic $entropy
if ( -not ( ValidateMnemonic $mnemonic ) ) { throw "invalid mnemonic phrase" }

$passphrase = $BWPassphrase             # to enhance security, set the passphrase as a BIP39 passphrase

$HMACSHA512 = New-Object Security.Cryptography.HMACSHA512
$seed       = PBKDF2 $mnemonic "mnemonic$passphrase" 2048 64 $HMACSHA512

echo "Entropy(Binary) : $entropy_b"
echo "Entropy(Hex)    : $entropy_h"
echo "BIP39 Mnemonic  : $mnemonic"
echo "BIP39Passphrase : $passphrase"
echo "Seed            : $seed"
