# cf. https://bitcoin.stackexchange.com/questions/121279/need-help-deriving-extended-private-key-from-bitcoin-root-extended-public-key-an
#
# Loading a library
# 
#  Please insert "Write-Host $il" at line 808 of BitcoinWallet.ps1.
. ./BitcoinWallet.ps1
#
# Settin up the problem
#
$xpub_root  = "xpub661MyMwAqRbcF2s3gyqdcUgw6dU7DjLGHCwkM9jndzGT8WXJjMxZiYnvNmfuzsEXC13FUn9BTeefy3uYf4Cj5k86iHUFzLS1yatpXN9hq4u" # m
$xprv_known = "xprvA3WvYTa5Xv4kSXuL9mAFMimc5psTTB1Dq8x4q9HB7R4EmpufsXFuhi9SpVVYXsmyjM5dvoGowU3W9hDuYRrgkQiiE1d881TZrFLhLNxBs7g" # m/44/0/0/1/404
$xprv_ans   = "xprvA3NPti2FcCNVfUfX7MHPJD6LTfdx2hHtB5kFfVAPj8LEtdUU8KWaRvg5MwR79hMESSUyvzYF1LxMctTUs5X6AFZcyHewmS2aSzp29oPqWc4" # m/44/0/0/0/402
#
# Solving the problem
#
( $w1 = [HDWallet]::new() ).ImportExtendedKey($xpub_root ,"m")
( $w2 = [HDWallet]::new() ).ImportExtendedKey($xprv_known,"m/44/0/0/1/404")
$null = $w1.Derive(44,$false).Derive(0,$false).Derive(0,$false).Derive(1,$false).Derive(404,$false)
$k   = [bigint]::Parse("0" + $w2.PrivateKey, "AllowHexSpecifier")
$i   = [bigint]::Parse("93796003022709312606780610282314876708735290129460570821564342040243358358345") # the 4th output of $il in Derive() method.
$kk  = $k  - $i  ; if ( $kk.Sign  -eq -1 ) { $kk  += [ECDSA]::Order }
$ii  = [bigint]::Parse("87404525788141400767421645722739302643580234366863609669219551197870192349415") # the 3rd output of $il in Derive() method.
$kkk = $kk - $ii ; if ( $kkk.Sign -eq -1 ) { $kkk += [ECDSA]::Order }
$w1.Derive(44,$false).Derive(0,$false).Derive(0,$false).PrivateKey = $kkk.ToString("x64") -replace '^0(?=[0-9a-f]{64}$)'
$xprv_got = $w1.Derive(44,$false).Derive(0,$false).Derive(0,$false).Derive(0,$false).Derive(402,$false).GetExtendedPrivateKey()
#
# Result
#
Write-Host "expected: $($xprv_ans)"
Write-Host "found   : $($xprv_got)"
