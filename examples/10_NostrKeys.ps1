
function GetNostrKeys {
    param( [string]$mnemonic, [int]$account = 0, [string]$passphrase = "" )
    $seed = GetBIP39Seed $mnemonic $passphrase
    $wallet = [HDWallet]::new( $seed )
    $prvkey = $wallet.Derive(44,$true).Derive(1237,$true).Derive($account,$true).Derive(0,$false).Derive(0,$false).PrivateKey 
    $pubkey = $wallet.Derive(44,$true).Derive(1237,$true).Derive($account,$true).Derive(0,$false).Derive(0,$false).PublicKey.Substring(2)
    $nsec = Bech32_Encode $prvkey "nsec" $false 0
    $npub = Bech32_Encode $pubkey "npub" $false 0
    return $nsec, $npub
}

$mnemonic12 = "leader monkey parrot ring guide accident before fence cannon height naive bean"
$mnemonic24 = "what bleak badge arrange retreat wolf trade produce cricket blur garlic valid proud rude strong choose busy staff weather area salt hollow arm fade"

$nsec1, $npub1 = GetNostrKeys $mnemonic12
$nsec2, $npub2 = GetNostrKeys $mnemonic24

Write-Output "mnemonic: $($mnemonic12)"
Write-Output "nsec    : $($nsec1)"
Write-Output "npub    : $($npub1)"
Write-Output "mnemonic: $($mnemonic24)"
Write-Output "nsec    : $($nsec2)"
Write-Output "npub    : $($npub2)"
