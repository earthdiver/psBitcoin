$HMACSHA512 = New-Object Security.Cryptography.HMACSHA512
$SHA256     = New-Object Security.Cryptography.SHA256CryptoServiceProvider

$mnemonic1   = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
$passphrase1 = ""
if ( -not ( ValidateMnemonic $mnemonic1 ) ) { throw "invalid mnemonic phrase (1)" }
$seed1   = PBKDF2 $mnemonic1 "mnemonic$passphrase1" 2048 64 $HMACSHA512
$wallet1 = [HDWallet]::new( $seed1 )
$fp1     = $wallet1.FingerPrint

write-Host "mnemonic1        : $mnemonic1"
Write-Host "seed1            : $seed1"

$mnemonic2   = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
$passphrase2 = ""
if ( -not ( ValidateMnemonic $mnemonic2 ) ) { throw "invalid mnemonic phrase (2)" }
$seed2   = PBKDF2 $mnemonic2 "mnemonic$passphrase2" 2048 64 $HMACSHA512
$wallet2 = [HDWallet]::new( $seed2 )
$fp2     = $wallet2.FingerPrint
write-Host "mnemonic2        : $mnemonic2"
Write-Host "seed2            : $seed2"
Write-Host

# P2WSH (BIP-0011,0048,0067,0141)
$Zprv1   = $wallet1.Derive(48,$true).Derive(0,$true).Derive(0,$true).Derive(2,$true).GetExtendedPrivatekey()
$Zpub2   = $wallet2.Derive(48,$true).Derive(0,$true).Derive(0,$true).Derive(2,$true).GetExtendedPublickey()   # co-signer's extended public key
( $w1 = [HDWallet]::new() ).ImportExtendedKey( $Zprv1, "m/48'/0'/0'/2'" )
( $w2 = [HDWallet]::new() ).ImportExtendedKey( $Zpub2, "m/48'/0'/0'/2'" )
$xprv1   = $w1.GetExtendedPrivatekey( $false, $true )
$xpub1   = $w1.GetExtendedPublickey( $false, $true )
$xpub2   = $w2.GetExtendedPublickey( $false, $true )
$dscrptr = "wsh(sortedmulti(2,[$($fp1)/48h/0h/0h/2h]$($xpub1)/<0;1>/*,[$($fp2)/48h/0h/0h/2h]$($xpub2)/<0;1>/*))"
$dscrptr = descsum_create $dscrptr
$Zpub1   = $w1.GetExtendedPublickey()
$prvkey1 = $w1.Derive(0,$false).Derive(0,$false).PrivateKey
$pubkey1 = $w1.Derive(0,$false).Derive(0,$false).PublicKey
$pubkey2 = $w2.Derive(0,$false).Derive(0,$false).PublicKey
$pk = @( $pubkey1, $pubkey2 ) | Sort-Object
$witnessScript = "52" + "21" + $pk[0] + "21" + $pk[1] + "52" + "ae" # OP_2 PUSH(pubkey) PUSH(pubkey) OP_2 OP_CHECKMULTISIG
$scriptHash    = i2h $SHA256.ComputeHash( ( h2i $witnessScript ) )
$address = Bech32_Encode $scriptHash "bc" $false 0
Write-Host "P2WSH (Native Segwit)"
Write-Host " derivation path : m/48'/0'/0'/2'"
Write-Host "   xprv1         : $xprv1"
Write-Host "   Zprv1         : $Zprv1"
Write-Host "   Zpub1         : $Zpub1"
Write-Host "   Zpub2         : $Zpub2"
Write-Host "   output desc.  : $dscrptr"
Write-Host " derivation path : m/48'/0'/0'/2'/0/0"
Write-Host "   privatekey1   : $prvkey1"
Write-Host "   publickey1    : $pubkey1"
Write-Host "   publickey2    : $pubkey2"
Write-Host "   address       : $address"
Write-Host

# P2SH-P2WSH (BIP-0011,0048,0067,0141)
$Yprv1   = $wallet1.Derive(48,$true).Derive(0,$true).Derive(0,$true).Derive(1,$true).GetExtendedPrivatekey()
$Ypub2   = $wallet2.Derive(48,$true).Derive(0,$true).Derive(0,$true).Derive(1,$true).GetExtendedPublickey()  # co-signer's extended public key
( $w1 = [HDWallet]::new() ).ImportExtendedKey( $Yprv1, "m/48'/0'/0'/1'" )
( $w2 = [HDWallet]::new() ).ImportExtendedKey( $Ypub2, "m/48'/0'/0'/1'" )
$xprv1   = $w1.GetExtendedPrivatekey( $false, $true )
$xpub1   = $w1.GetExtendedPublickey( $false, $true )
$xpub2   = $w2.GetExtendedPublickey( $false, $true )
$dscrptr = "sh(wsh(sortedmulti(2,[$($fp1)/48h/0h/0h/1h]$($xpub1)/<0;1>/*,[$($fp2)/48h/0h/0h/1h]$($xpub2)/<0;1>/*)))"
$dscrptr = descsum_create $dscrptr
$Ypub1   = $w1.GetExtendedPublickey()
$prvkey1 = $w1.Derive(0,$false).Derive(0,$false).PrivateKey
$pubkey1 = $w1.Derive(0,$false).Derive(0,$false).PublicKey
$pubkey2 = $w2.Derive(0,$false).Derive(0,$false).PublicKey
$pk = @( $pubkey1, $pubkey2 ) | Sort-Object
$witnessScript = "52" + "21" + $pk[0] + "21" + $pk[1] + "52" + "ae"
$redeemScript = "0020" + ( i2h $SHA256.ComputeHash( ( h2i $witnessScript ) ) )  # 0020: witnessversion(0) + push32bytes
$scriptHash = HASH160 $redeemScript
$address = Base58Check_Encode ( "05" + $scriptHash ) 
Write-Host "P2SH-P2WSH (Nested Segwit)"
Write-Host " derivation path : m/48'/0'/0'/1'"
Write-Host "   xprv1         : $xprv1"
Write-Host "   Yprv1         : $Yprv1"
Write-Host "   Ypub1         : $Ypub1"
Write-Host "   Ypub2         : $Ypub2"
Write-Host "   output desc.  : $dscrptr"
Write-Host " derivation path : m/48'/0'/0'/1'/0/0"
Write-Host "   privatekey1   : $prvkey1"
Write-Host "   publickey1    : $pubkey1"
Write-Host "   publickey2    : $pubkey2"
Write-Host "   address       : $address"
Write-Host

# P2SH (BIP-0011,0016,0045,0067)
$xprv1   = $wallet1.Derive(45,$true).GetExtendedPrivatekey()
$xpub2   = $wallet2.Derive(45,$true).GetExtendedPublickey()  # co-signer's extended public key
( $w1 = [HDWallet]::new() ).ImportExtendedKey( $xprv1, "m/45'" )
( $w2 = [HDWallet]::new() ).ImportExtendedKey( $xpub2, "m/45'" )
$xpub1   = $w1.GetExtendedPublickey()
$dscrptr = "sh(sortedmulti(2,[$($fp1)/45h]$($xpub1)/<0;1>/*,[$($fp2)/45h]$($xpub2)/<0;1>/*))"
$dscrptr = descsum_create $dscrptr
$prvkey1 = $w1.Derive(0,$false).Derive(0,$false).PrivateKey                    # BlueWallet, Sparrow
$pubkey1 = $w1.Derive(0,$false).Derive(0,$false).PublicKey                     # BlueWallet, Sparrow
$pubkey2 = $w2.Derive(0,$false).Derive(0,$false).PublicKey                     # BlueWallet, Sparrow
#$prvkey1 = $w1.Derive(0,$false).Derive(0,$false).Derive(0,$false).PrivateKey   # Electrum (BIP-0045)
#$pubkey1 = $w1.Derive(0,$false).Derive(0,$false).Derive(0,$false).PublicKey    # Electrum (BIP-0045)
#$pubkey2 = $w2.Derive(0,$false).Derive(0,$false).Derive(0,$false).PublicKey    # Electrum (BIP-0045)
$pk = @( $pubkey1, $pubkey2 ) | Sort-Object
$redeemScript = "52" + "21" + $pk[0] + "21" + $pk[1] + "52" + "ae"
$scriptHash = HASH160 $redeemScript
$address = Base58Check_Encode ( "05" + $scriptHash ) 
Write-Host "P2SH (Legacy)"
Write-Host " derivation path : m/45'"
Write-Host "   xprv1         : $xprv1"
Write-Host "   xpub1         : $xpub1"
Write-Host "   xpub2         : $xpub2"
Write-Host "   output desc.  : $dscrptr"
Write-Host " derivation path : m/45'/0/0"
Write-Host "   privatekey1   : $prvkey1"
Write-Host "   publickey1    : $pubkey1"
Write-Host "   publickey2    : $pubkey2"
Write-Host "   address       : $address"
