echo "<<< HD Wallets BIP44,49,84,86 >>>"
$seed = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
$w = [HDWallet]::new( $seed )
echo "BIP32 Root Private Key  : $($w.GetExtendedPrivateKey())"

echo ""
$w.Derive(44,$true).Derive(0,$true).Derive(0,$true).Path
$w.Derive(44,$true).Derive(0,$true).Derive(0,$true).GetExtendedPrivateKey()
$w.Derive(44,$true).Derive(0,$true).Derive(0,$true).GetExtendedPublicKey()
$w.Derive(44,$true).Derive(0,$true).Derive(0,$true).Derive(0,$false).Derive(0,$false).Path
$w.Derive(44,$true).Derive(0,$true).Derive(0,$true).Derive(0,$false).Derive(0,$false).GetPrivateKey_WIF()
$w.Derive(44,$true).Derive(0,$true).Derive(0,$true).Derive(0,$false).Derive(0,$false).GetAddressP2PKH()

echo ""
$w.Derive(49,$true).Derive(0,$true).Derive(0,$true).Path
$w.Derive(49,$true).Derive(0,$true).Derive(0,$true).GetExtendedPrivateKey()
$w.Derive(49,$true).Derive(0,$true).Derive(0,$true).GetExtendedPrivateKey() | Set-Variable yprv
$w.Derive(49,$true).Derive(0,$true).Derive(0,$true).GetExtendedPublicKey()
$w.Derive(49,$true).Derive(0,$true).Derive(0,$true).Derive(0,$false).Derive(0,$false).Path
$w.Derive(49,$true).Derive(0,$true).Derive(0,$true).Derive(0,$false).Derive(0,$false).GetPrivateKey_WIF()
$w.Derive(49,$true).Derive(0,$true).Derive(0,$true).Derive(0,$false).Derive(0,$false).GetAddressP2SHP2WPKH()

echo ""
$w.Derive(84,$true).Derive(0,$true).Derive(0,$true).Path
$w.Derive(84,$true).Derive(0,$true).Derive(0,$true).GetExtendedPrivateKey()
$w.Derive(84,$true).Derive(0,$true).Derive(0,$true).GetExtendedPublicKey()
$w.Derive(84,$true).Derive(0,$true).Derive(0,$true).GetExtendedPublicKey() | Set-Variable zpub
$w.Derive(84,$true).Derive(0,$true).Derive(0,$true).Derive(0,$false).Derive(0,$false).Path
$w.Derive(84,$true).Derive(0,$true).Derive(0,$true).Derive(0,$false).Derive(0,$false).GetPrivateKey_WIF()
$w.Derive(84,$true).Derive(0,$true).Derive(0,$true).Derive(0,$false).Derive(0,$false).GetAddressP2WPKH()

echo ""
$w.Derive(86,$true).Derive(0,$true).Derive(0,$true).Path
$w.Derive(86,$true).Derive(0,$true).Derive(0,$true).GetExtendedPrivateKey()
$w.Derive(86,$true).Derive(0,$true).Derive(0,$true).GetExtendedPublicKey()
$w.Derive(86,$true).Derive(0,$true).Derive(0,$true).Derive(0,$false).Derive(0,$false).Path
$w.Derive(86,$true).Derive(0,$true).Derive(0,$true).Derive(0,$false).Derive(0,$false).GetPrivateKey_WIF()
$w.Derive(86,$true).Derive(0,$true).Derive(0,$true).Derive(0,$false).Derive(0,$false).GetAddressP2TR()

echo ""
# Importing the BIP49 extended private key
( $y = [HDWallet]::new() ).ImportExtendedKey( $yprv, "m/49'/0'/0'", 0 )
$y.GetExtendedPrivateKey()
$y.GetExtendedPublicKey()
$y.Derive(0,$false).Derive(0,$false).Path
$y.Derive(0,$false).Derive(0,$false).GetPrivateKey_WIF()
$y.Derive(0,$false).Derive(0,$false).GetAddressP2SHP2WPKH()

echo ""
# Importing the BIP84 extended public key
( $z = [HDWallet]::new() ).ImportExtendedKey( $zpub, "m/84'/0'/0'", 0 )
$z.GetExtendedPrivateKey()
$z.GetExtendedPublicKey()
$z.Derive(0,$false).Derive(0,$false).Path
$z.Derive(0,$false).Derive(0,$false).GetPrivateKey_WIF()
$z.Derive(0,$false).Derive(0,$false).GetAddressP2WPKH()
