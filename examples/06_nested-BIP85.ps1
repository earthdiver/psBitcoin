$wordList   = 0 # 1 for Japanese
$words      = 12
$mnemonic   = "install scatter logic circle pencil average fall shoe quantum disease suspect usage"
$passphrase = ""
$seed       = GetBIP39Seed $mnemonic $passphrase
$ng         = 3
$indices    = @( 3, 1, 2009 )
$BIP85HMAC  = New-Object Security.Cryptography.HMACSHA512
try {
    $BIP85HMAC.Key = [Text.Encoding]::UTF8.GetBytes( "bip-entropy-from-k" )
    for ( $i=0; $i -lt $ng; $i++ ) {
        $w    = [HDWallet]::new( $seed )
        $key  = $w.Derive( 83696968, 1 ).Derive( 39, 1 ).Derive( $wordList, 1 ).Derive( $words, 1 ).Derive( $indices[$i], 1 ).PrivateKey
        $entropy = ( $BIP85HMAC.ComputeHash( ( h2i $key ) ) )[0..($words*4/3-1)]
        if ( $wordList -eq 1 ) {
            $new_mnemonic = GetMnemonic -j $entropy
        } else {
            $new_mnemonic = GetMnemonic    $entropy
        }
        $seed = GetBIP39Seed $new_mnemonic "" -Japanese:($wordList -eq 1)
    }
} finally {
    $BIP85HMAC.Dispose()
}
echo "original mnemonic code : $mnemonic"
echo "new      mnemonic code : $new_mnemonic"
