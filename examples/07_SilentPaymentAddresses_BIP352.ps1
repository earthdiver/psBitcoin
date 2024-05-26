###########
$network    = "mainnet"
$mnemonic   = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
$passphrase = ""
$labels     = @( "", "0", "1", "2" )
###########
if ( -not ( ValidateMnemonic $mnemonic ) ) { throw "invalid mnemonic phrase" }
if ( $network -eq "mainnet" ) {
    $hrp      = "sp"
    $coinType = 0
} else {
    $hrp      = "tsp"
    $coinType = 1
}
$seed = PBKDF2 $mnemonic "mnemonic$passphrase" 2048 64 (New-Object Security.Cryptography.HMACSHA512)
$w = [HDWallet]::new( $seed )
$B_Spend_priv = $w.Derive(352,$true).Derive($coinType,$true).Derive(0,$true).Derive(0,$true).Derive(0,$false).PrivateKey
$B_Spend_pub  = $w.Derive(352,$true).Derive($coinType,$true).Derive(0,$true).Derive(0,$true).Derive(0,$false).PublicKey
$B_Scan_priv  = $w.Derive(352,$true).Derive($coinType,$true).Derive(0,$true).Derive(1,$true).Derive(0,$false).PrivateKey
$B_Scan_pub   = $w.Derive(352,$true).Derive($coinType,$true).Derive(0,$true).Derive(1,$true).Derive(0,$false).PublicKey
echo "spend_priv_key      : $B_Spend_priv"
echo " scan_priv_key      : $B_Scan_priv"
$SHA256 = New-Object Cryptography.SHA256CryptoServiceProvider
foreach ( $label in $labels ) {
    if ( $label -eq "" ) {
        $B_m_pub = $B_Spend_pub
    } else {
        $G = [ECDSA]::new()
        $k = [bigint]::Parse( "0" + $B_Spend_priv, "AllowHexSpecifier" )
        $B = $G * $k
        if ( -not $B.Y.IsEven ) { $k = [ECDSA]::Order - $k }
        $tag    = [Text.Encoding]::UTF8.GetBytes( "BIP0352/Label" )
        $hash   = $SHA256.ComputeHash( $SHA256.ComputeHash( $tag ) * 2 + ( h2i ( $B_Scan_priv + ([UInt32]$label).ToString( "x8" ) ) ) )
        $tweak  = [bigint]::new( $hash[31..0] + @(0x00) )
        if ( $tweak.IsZero -or $tweak -ge [ECDSA]::Order ) {
            throw "Tweak is zero or greater than the order of the curve - 1."
        }
        $B_m = $B + $G * $tweak
        if ( $B_m -eq $null ) { throw "The resulting address is invalid." }
        if ( $B_m.Y.IsEven ) {
            $B_m_pub = "02" + ( $B_m.X.ToString( "x64" ) -replace '^0(?=[0-9a-f]{64}$)' )
        } else {
            $B_m_pub = "03" + ( $B_m.X.ToString( "x64" ) -replace '^0(?=[0-9a-f]{64}$)' )
        }
    }
    $silentAddress = Bech32_Encode ( $B_Scan_pub + $B_m_pub ) $hrp $true 0
    $comment = if ( $label -eq "0" ) { " # for change" } else { "" }
    echo "address (label:$($label.PadLeft( 4, ' ' ))): $silentAddress $comment"
}
