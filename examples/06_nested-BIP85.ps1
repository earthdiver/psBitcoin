$wordList   = 0 # 1 for Japanese
$words      = 12
$mnemonic   = "install scatter logic circle pencil average fall shoe quantum disease suspect usage"
$passphrase = ""
$HMACSHA512 = New-Object Security.Cryptography.HMACSHA512
$seed       = PBKDF2 $mnemonic "mnemonic$passphrase" 2048 64 $HMACSHA512
$ng         = 3
$indices    = @( 3, 1, 2009 )
for ( $i=0; $i -lt $ng; $i++ ) {
    $w    = [HDWallet]::new( $seed )
    $key  = $w.Derive( 83696968, 1 ).Derive( 39, 1 ).Derive( $wordList, 1 ).Derive( $words, 1 ).Derive( $indices[$i], 1 ).PrivateKey
    $HMACSHA512.Key = [Text.Encoding]::UTF8.GetBytes( "bip-entropy-from-k" )
    $entropy = ( $HMACSHA512.ComputeHash( ( h2i $key ) ) )[0..($words*4/3-1)]
    if ( $wordList -eq 1 ) {
        $new_mnemonic = GetMnemonic -j $entropy
    } else {
        $new_mnemonic = GetMnemonic    $entropy
    }
    $seed = PBKDF2 $new_mnemonic "mnemonic" 2048 64 $HMACSHA512
}
echo "original mnemonic code : $mnemonic"
echo "new      mnemonic code : $new_mnemonic"
