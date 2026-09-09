# Public LND aezeed test vector. Never use this mnemonic for funds.
# Generated with LND v0.19.3-beta, production scrypt N=32768.
# Source: tests/reference/aezeed/main.go (first vector).
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'BitcoinWallet.ps1')

function GetAezeedSeed {
    <#
    .SYNOPSIS
    Decodes an LND aezeed v0 mnemonic to the 16-byte BIP32 seed (hex).
    .DESCRIPTION
    Uses the English wordlist, scrypt and AEZ authentication, not BIP39.
    The optional passphrase is the aezeed passphrase, not the wallet password.
    Passphrase bytes are UTF-8 without trimming or Unicode normalization.
    #>
    param( [Parameter(Mandatory=$True,ValueFromPipeline=$True)][string]$mnemonic,
           [AllowEmptyString()][string]$passphrase = ""
    )
    begin {
        $wordlist = GetBIP39Wordlist
        if ( $wordlist.Count -ne 2048 ) { throw "aezeed requires the 2048-word English wordlist" }
        # Use a new type name so a previously loaded decoder with an internal
        # version restriction cannot be reused after this script is reloaded.
        if ( -not ( 'PsBitcoin.AezeedEntropyDecoder' -as [type] ) ) {
            $definitionFile = ( Get-Command GetAezeedSeed -CommandType Function ).ScriptBlock.File
            Add-Type -Path ( Join-Path ( Split-Path -Parent $definitionFile ) 'Aezeed.cs' ) -ErrorAction Stop
        }
    }
    process {
        $words = $mnemonic.Trim().ToLowerInvariant() -split '\s+'
        if ( $words.Count -ne 24 ) { throw "aezeed requires exactly 24 English words" }
        $bits = foreach ( $word in $words ) {
            $index = $wordlist.IndexOf( $word )
            if ( $index -lt 0 ) { throw "Unknown aezeed word; check the English mnemonic" }
            [Convert]::ToString( $index, 2 ).PadLeft( 11, '0' )
        }
        [byte[]]$encoded = ( $bits -join '' ) | b2i
        [byte[]]$passwordBytes = [Text.Encoding]::UTF8.GetBytes( $passphrase )
        $entropy = $null
        try {
            $entropy = [PsBitcoin.AezeedEntropyDecoder]::Decode( $encoded, $passwordBytes )
            return ( i2h $entropy )
        } finally {
            [Array]::Clear( $passwordBytes, 0, $passwordBytes.Length )
            [Array]::Clear( $encoded, 0, $encoded.Length )
            if ( $null -ne $entropy ) { [Array]::Clear( $entropy, 0, $entropy.Length ) }
        }
    }
}

# The 16-byte entropy is used directly as the BIP32 seed.
$mnemonic = 'ability broccoli ritual pony acoustic shiver ignore train vault surge miracle mutual reason swamp warm head youth pool able yellow avocado vast face already'
$passphrase = ''
$seed = GetAezeedSeed -mnemonic $mnemonic -passphrase $passphrase

"Aezeed mnemonic: $mnemonic"
"Passphrase: (empty)"
"Seed: $seed"
