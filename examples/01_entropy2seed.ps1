echo "<<< BIP39 >>>"
$entropy   = @()                                                       # Entropy (in byte array),    multiple of  4 greater than or equal to  16
$entropy_h = "00000000000000000000000000000000"                        # Entropy (in hex string),    multiple of  8 greater than or equal to  32
$entropy_b = ""                                                        # Entropy (in binary string), multiple of 32 greater than or equal to 128
$entropy_d = ""                                                        # Entropy (in base 6 number, digits ranging from 1 to 6)
#$entropy_d = "12345612345612345612345612345612345612345612345612345"  # Roll dice  53 times (128 bits)
                                                                       # Roll dice 103 times (256 bits)

$passphrase = ""

if ( $entropy ) {
   # dummy
} elseif ( $entropy_h ) {
   $entropy = h2i $entropy_h
} elseif ( $entropy_b ) {
   $entropy = b2i $entropy_b
} elseif ( $entropy_d ) {
   if ( $entropy_d.Length -eq 53 ) {
      $nbits = 128
   } elseif ( $entropy_d.Length -eq 103 ) {
      $nbits = 256
   } else {
      throw "dice entropy must contain exactly 53 or 103 rolls"
   }
   $nbytes  = $nbits / 8
#  $SHA256  = New-Object Security.Cryptography.SHA256CryptoServiceProvider                               # for compatibility with coldcard, seedsigner, 
#  $entropy = $SHA256.ComputeHash( [Text.Encoding]::ASCII.GetBytes( $entropy_d ) )[0..($nbytes-1)]       #  krux, iancoleman, etc.
   $i = [bigint]::Zero
   foreach ( $c in $entropy_d.ToCharArray() ) {
      $digit = "123456".IndexOf( $c )
      if ( $digit -lt 0 ) { throw "invalid character '$c'" }
      $i = $i * 6 + $digit
   }
   $range = [bigint]::Pow( 2, $nbits )
   $space = [bigint]::Pow( 6, $entropy_d.Length )
   $limit = ( $space / $range ) * $range
   if ( $i -ge $limit ) { throw "rolls fell in the rejection range; reroll the complete set" }
   $i %= $range
   $entropy_h = ( $i.ToString( "x" ) -replace '^0+', '' ).PadLeft( $nbytes * 2, "0" )
   $entropy = h2i $entropy_h
} else {
   # Generate entropy from random if not specified (change $nbits to 256 to get 24 words)
   $nbits   = 128
   $nbytes  = $nbits / 8
   $entropy = [byte[]]::new( $nbytes )
   [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes( $entropy )
}
if ( -not $entropy_b ) { $entropy_b = i2b $entropy }
if ( -not $entropy_h ) { $entropy_h = i2h $entropy }

$mnemonic  = GetMnemonic $entropy

# Directly set the mnemonic as needed.
#$mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

if ( -not ( ValidateMnemonic $mnemonic ) ) { throw "invalid mnemonic phrase" }

$seed = GetBIP39Seed $mnemonic $passphrase

echo "Entropy(Binary) : $entropy_b"
echo "Entropy(Hex)    : $entropy_h"
echo "BIP39 Mnemonic  : $mnemonic"
echo "BIP39Passphrase : $passphrase"
echo "Seed            : $seed"


echo "<<< BIP32 >>>"
$version        = "0488ade4"     # BIP32 private key
$depth          = "00"
$pFingerprint   = "00000000"     # The first 4 bytes of the hash value of the parent public key, "00000000" for the root
$childnumber    = "00000000"
$BIP32HMAC = New-Object Security.Cryptography.HMACSHA512
try {
   $BIP32HMAC.Key = [Text.Encoding]::UTF8.GetBytes("Bitcoin seed")
   $extendedkey   = i2h $BIP32HMAC.ComputeHash( ( h2i $seed ) )
} finally {
   $BIP32HMAC.Dispose()
}
$privatekey     = "00" + $extendedkey.Substring( 0, 64 )
$chaincode      =        $extendedkey.Substring( 64 ,64 )
$serialized     = $version + $depth + $pFingerprint + $childnumber + $chaincode + $privatekey
$xprv           = Base58Check_Encode $serialized
echo "BIP32 Root Key  : $xprv"
