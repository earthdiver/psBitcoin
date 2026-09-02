#
# classes and functions for bitcoin transactions
#
# Copyright (c) 2023-2025 earthdiver1
#
# This work is licensed under the Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0).
#

function UInt32toStr( [UInt32]$int ) {
    $bytes = [BitConverter]::GetBytes( $int )
    if ( -not [BitConverter]::IsLittleEndian ) {
        [Array]::Reverse( $bytes )
    }
    return [BitConverter]::ToString( $bytes ).Replace("-","").ToLower()
}

function UInt64toStr( [UInt64]$int ) {
    $bytes = [BitConverter]::GetBytes( $int )
    if ( -not [BitConverter]::IsLittleEndian ) {
        [Array]::Reverse( $bytes )
    }
    return [BitConverter]::ToString( $bytes ).Replace("-","").ToLower()
}

function VarInttoStr( [UInt64]$int ) {
    $xstr = UInt64toStr $int
    switch ( $int ) {
        { $_ -le 0x000000fc } { $result =        $xstr.Substring( 0, 2 ) ; break }
        { $_ -le 0x0000ffff } { $result = "fd" + $xstr.Substring( 0, 4 ) ; break }
        { $_ -le 0xffffffff } { $result = "fe" + $xstr.Substring( 0, 8 ) ; break }
        default               { $result = "ff" + $xstr                        }
    }
    return $result
}

function ConvertTo-CompactSizeHex ( [string]$str ) {
    if ( $str.Length % 2 -ne 0 ) { throw "invalid hex string length" }
    return ( VarInttoStr ( $str.Length / 2 ) ) + $str
}

function Push ( [string]$str ) {
    if ( $str.Length % 2 -ne 0 ) { throw "invalid hex string length" }
    [UInt32]$size = $str.Length / 2
    $xstr = UInt32toStr $size
    switch ( $size ) {
        { $_ -le 75     } { $result =        $xstr.Substring( 0, 2 ) + $str ; break }
        { $_ -le 0xff   } { $result = "4c" + $xstr.Substring( 0, 2 ) + $str ; break }
        { $_ -le 0xffff } { $result = "4d" + $xstr.Substring( 0, 4 ) + $str ; break }
        default           { $result = "4e" + $xstr.Substring( 0, 8 ) + $str         }
    }
    return $result
}

function GetDustThreshold ( [string]$scriptPubKey ) {
    switch -Regex ( $scriptPubKey ) {
        '^0014'        { return [UInt64]294 } # P2WPKH
        '^(0020|5120)' { return [UInt64]330 } # P2WSH, P2TR
        '^a914'        { return [UInt64]540 } # P2SH
        '^76a914'      { return [UInt64]546 } # P2PKH
        default        { return [UInt64]546 }
    }
}

function AssertPaymentAmount ( [UInt64]$amount, [UInt64]$fee, [string]$scriptPubKey ) {
    [UInt64]$maxMoney = 2100000000000000
    if ( [bigint]$amount + [bigint]$fee -gt [bigint]$maxMoney ) {
        throw "amount and fee exceed MAX_MONEY"
    }
    if ( $amount -lt ( GetDustThreshold $scriptPubKey ) ) {
        throw "destination amount is below the dust threshold"
    }
}

function ConvertTo-ScriptNumHex ( [UInt64]$value ) {
    if ( $value -eq 0 ) { return "" }
    $bytes = [Collections.Generic.List[byte]]::new()
    while ( $value -gt 0 ) {
        $bytes.Add( [byte]( $value -band 0xff ) )
        $value = $value -shr 8
    }
    if ( ( $bytes[$bytes.Count - 1] -band 0x80 ) -ne 0 ) {
        $bytes.Add( 0 )
    }
    return i2h ( $bytes.ToArray() )
}

class TXin {
    [string]$txid
    [string]$index
    [string]$SSLen
    [string]$scriptSig
    [string]$sequence
    TXin ( [string]$txid, [UInt32]$index ) {
        $this.Init( $txid, $index, "",         [UInt32]::MaxValue - 2)   # enable opt-in RBF (BIP-0125)
    }
    TXin ( [string]$txid, [UInt32]$index, [string]$scriptSig ) {
        $this.Init( $txid, $index, $scriptSig, [UInt32]::MaxValue - 2 )  # enable opt-in RBF (BIP-0125)
    }
    TXin ( [string]$txid, [UInt32]$index, [string]$scriptSig, [UInt32]$sequence ) {
        $this.Init( $txid, $index, $scriptSig, $sequence )
    }
    hidden [void] Init ( [string]$txid, [UInt32]$index, [string]$scriptSig, [UInt32]$sequence ) {
        if ( $txid.Length -ne 64 ) { throw "invlid txid" }
        if ( $scriptSig.Length % 2 -ne 0 ) { throw "invalid scriptSig" }
        $sb = [Text.StringBuilder]::new( $txid.Length )
        for ( $i = ($txid.Length - 1); $i -ge 0; $i-=2 ) {
            [void]$sb.Append( $txid.Chars($i-1) )
            [void]$sb.Append( $txid.Chars($i)   )
        }
        $this.txid      = $sb.ToString()
        $this.index     = UInt32toStr $index
        $this.SSLen     = VarInttoStr ( $scriptSig.Length / 2 )
        $this.scriptSig = $scriptSig
        $this.sequence  = UInt32toStr $sequence
    }
}

class TXout {
    [string]$value
    [string]$SPLen
    [string]$scriptPubKey
    TXout ( [UInt64]$value, [string]$scriptPubKey ) {
        if ( $scriptPubKey.Length % 2 -ne 0 ) { throw "invalid scriptPubkey" }
        $this.value        = UInt64toStr $value
        $this.SPLen        = VarInttoStr ( $scriptPubKey.Length / 2 )
        $this.scriptPubKey = $scriptPubKey
    }
}

class Witness {
    [string]$count
    [string[]]$witness_items
    Witness () {
        $this.count = "00"
        $this.witness_items = @()
    }
    Witness ( [string[]]$witness_items ) {
        $this.count         = VarInttoStr $witness_items.Length
        $this.witness_items = $witness_items
    }
}

class TX {
    [string]$version
    [string]$txin_count
    [TXin[]]$txins
    [string]$txout_count
    [TXout[]]$txouts
    [string]$lock_time
    TX ( [TXin[]]$txins, [TXout[]]$txouts ) {
        $this.Init( 2,        $txins, $txouts, 0 )
    }
    TX ( [UInt32]$version, [TXin[]]$txins, [TXout[]]$txouts, [Uint32]$lock_time ) {
        $this.Init( $version, $txins, $txouts, $lock_time )
    }
    hidden [void] Init ( [UInt32]$version, [TXin[]]$txins, [TXout[]]$txouts, [Uint32]$lock_time ) {
        $this.version     = UInt32toStr $version
        $this.txin_count  = VarInttoStr $txins.Length
        $this.txins       = $txins
        $this.txout_count = VarInttoStr $txouts.Length
        $this.txouts      = $txouts
        $this.lock_time   = UInt32toStr $lock_time
    }
}

class TXS {
    [string]$version
    [string]$marker
    [string]$flag
    [string]$txin_count
    [TXin[]]$txins
    [string]$txout_count
    [TXout[]]$txouts
    [Witness[]]$witnesses
    [string]$lock_time
    TXS ( [TXin[]]$txins, [TXout[]]$txouts ) {
        $this.Init( 2,        0,       1,     $txins, $txouts, @( [Witness]::new() ), 0 )
    }
    TXS ( [TXin[]]$txins, [TXout[]]$txouts, [Witness[]]$witnesses ) {
        $this.Init( 2,        0,       1,     $txins, $txouts, $witnesses, 0 )
    }
    TXS ( [UInt32]$version, [Byte]$marker, [Byte]$flag, [TXin[]]$txins, [TXout[]]$txouts, [Witness[]]$witnesses, [UInt32]$lock_time ) {
        $this.Init( $version, $marker, $flag, $txins, $txouts, $witnesses, $lock_time )
    }
    hidden [void] Init( [UInt32]$version,
                        [Byte]$marker,
                        [Byte]$flag,
                        [TXin[]]$txins,
                        [TXout[]]$txouts,
                        [Witness[]]$witnesses,
                        [UInt32]$lock_time
                      ) {
        $this.version     = UInt32toStr $version
        $this.marker      = $marker.ToString( "x2" )
        $this.flag        = $flag.ToString( "x2" )
        $this.txin_count  = VarInttoStr $txins.Length
        $this.txins       = $txins
        $this.txout_count = VarInttoStr $txouts.Length
        $this.txouts      = $txouts
        $this.witnesses   = $witnesses
        $this.lock_time   = UInt32toStr $lock_time
    }
}

class SegwitMsg {
    [string]$nVersion
    [string]$hashPrevouts
    [string]$hashSequence
    [string]$outpoint
    [string]$scriptCode
    [string]$value
    [string]$nSequence
    [string]$hashOutputs
    [string]$nLocktime
    [string]$sighash_type
    SegwitMsg ( [TXS]$tx, [UInt32]$ntx, [string]$scriptCode, [UInt64]$value ) {
        $this.Init( $tx, $ntx, $scriptCode, $value, 1 )
    }
    SegwitMsg ( [TXS]$tx, [UInt32]$ntx, [string]$scriptCode, [UInt64]$value, [UInt32]$sighashType ) {
        $this.Init( $tx, $ntx, $scriptCode, $value, $sighashType )
    }
    hidden Init ( [TXS]$tx, [UInt32]$ntx, [string]$scriptCode, [UInt64]$value, [UInt32]$sighashType ) {
        if ( $null -eq $tx ) { throw "'tx' must not be null." }
        if ( $ntx -ge $tx.txins.Length ) { throw "'ntx' must be smaller than the size of 'tx.txins'." }
        if ( $sighashType -notin ( 0x01, 0x02, 0x03, 0x81, 0x82, 0x83 ) ) { throw "invalid sighash type" }

# SIGHASH_ALL          : 0x01
# SIGHASH_NONE         : 0x02
# SIGHASH_SINGLE       : 0x03
# SIGHASH_ANYONECANPAY : 0x80

        $prevouts = ""
        $sequences = ""
        $outputs = ""
        for ( $i = 0; $i -lt $tx.txins.Length; $i++ ) {
            $prevouts  += $tx.txins[$i].txid + $tx.txins[$i].index
            $sequences += $tx.txins[$i].sequence
        }
        for ( $i = 0; $i -lt $tx.txouts.Length; $i++ ) {
            $outputs += $tx.txouts[$i].ToString()
        }
        $this.nVersion = $tx.version
        if ( ( $sighashType -band 0x80 ) -eq 0 ) {
            $this.hashPrevouts = Hash256 $prevouts
        } else {
            $this.hashPrevouts = "00" * 32
        }
        if ( ( $sighashType -band 0x82 ) -eq 0 ) {
            $this.hashSequence = Hash256 $sequences
        } else {
            $this.hashSequence = "00" * 32
        }
        $this.outpoint   = $tx.txins[$ntx].txid + $tx.txins[$ntx].index
        $this.scriptCode = $scriptCode
        $this.value      = UInt64toStr $value
        $this.nSequence  = $tx.txins[$ntx].sequence
        if ( ( $sighashType -band 0x02 ) -eq 0 ) {
            $this.hashOutputs = Hash256 $outputs
        } elseif ( ( $sighashType -band 0x1f ) -eq 0x03 -and $ntx -lt $tx.txouts.Length ) {
            $this.hashOutputs = Hash256 $tx.txouts[$ntx].ToString()
        } else {
            $this.hashOutputs = "00" * 32
        }
        $this.nLocktime    = $tx.lock_time
        $this.sighash_type = UInt32toStr $sighashType
    }
}

class TaprootMsg {
    [string]$hash_type
    [string]$nVersion
    [string]$nLockTime
    [string]$sha_prevouts
    [string]$sha_amounts
    [string]$sha_scriptpubkeys
    [string]$sha_sequences
    [string]$sha_outputs
    [string]$spend_type
    [string]$outpoint
    [string]$amount
    [string]$scriptPubKey
    [string]$nSequence
    [string]$input_index
    [string]$sha_annex
    [string]$sha_single_output
# extension
    [string]$tapleaf_hash
    [string]$key_version
    [string]$codesep_pos
    TaprootMsg ( [TXS]$tx, [UInt32]$ntx, [string[]]$scripts, [UInt64[]]$values ) {
        $this.Init( $tx, $ntx, $scripts, $values, 0x00, 0, "", "" )
    }
    TaprootMsg ( [TXS]$tx, [UInt32]$ntx, [string[]]$scripts, [UInt64[]]$values, [byte]$sighashType ) {
        $this.Init( $tx, $ntx, $scripts, $values, $sighashType, 0, "", "" )
    }
    TaprootMsg ( [TXS]$tx, [UInt32]$ntx, [string[]]$scripts, [UInt64[]]$values, [byte]$sighashType, [byte]$ext_flag, [string]$annex, [string]$tapleaf_hash ) {
        $this.Init( $tx, $ntx, $scripts, $values, $sighashType, $ext_flag, $annex, $tapleaf_hash )
    }
    hidden Init ( [TXS]$tx, [UInt32]$ntx, [string[]]$scripts, [UInt64[]]$values, [byte]$sighashType, [byte]$ext_flag, [string]$annex, [string]$tapleaf_hash ) {
        if ( $null -eq $tx ) { throw "'tx' must not be null." }
        if ( $ntx -ge $tx.txins.Length ) { throw "'ntx' must be smaller than the size of 'tx.txins'." }
        if ( $scripts.Length -lt $tx.txins.Length -or $values.Length -lt $tx.txins.Length ) {
            throw "'scripts' and 'values' must contain an entry for every input."
        }
        if ( $sighashType -notin ( 0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83 ) ) { throw "invalid sighash type" }
        if ( ( $sighashType -band 0x03 ) -eq 3 ) {
            if ( $ntx -ge $tx.txouts.Length ) { throw "'ntx' must be smaller than the size of 'tx.txouts'." }
        }
        if ( $ext_flag -notin ( 0, 1 ) ) { throw "invalid 'ext_flag'" }
        if ( $ext_flag -eq 1 -and $tapleaf_hash.Length -ne 64 ) { throw "inconsistent 'ext_flag' and 'tapleaf_hash'" }
        if ( $ext_flag -eq 0 -and $tapleaf_hash ) { throw "inconsistent 'ext_flag' and 'tapleaf_hash'" }

# SIGHASH_DEFAULT      : 0x00
# SIGHASH_ALL          : 0x01
# SIGHASH_NONE         : 0x02
# SIGHASH_SINGLE       : 0x03
# SIGHASH_ANYONECANPAY : 0x80

        $SHA256 = New-Object Cryptography.SHA256CryptoServiceProvider
        $this.hash_type = $sighashType.ToString( "x2" )
        $this.nVersion  = $tx.version
        $this.nLockTime = $tx.lock_time
        if ( ( $sighashType -band 0x80 ) -eq 0 ) {
            $prevouts      = ""
            $amounts       = ""
            $scriptpubkeys = ""
            $sequences     = ""
            for ( $i = 0; $i -lt $tx.txins.Length; $i++ ) {
                $prevouts      += $tx.txins[$i].txid + $tx.txins[$i].index
                $amounts       += UInt64toStr $values[$i]
                $scriptpubkeys += ConvertTo-CompactSizeHex $scripts[$i]
                $sequences     += $tx.txins[$i].sequence
            }
            $this.sha_prevouts      = i2h $SHA256.ComputeHash( ( h2i $prevouts      ) )
            $this.sha_amounts       = i2h $SHA256.ComputeHash( ( h2i $amounts       ) )
            $this.sha_scriptpubkeys = i2h $SHA256.ComputeHash( ( h2i $scriptpubkeys ) )
            $this.sha_sequences     = i2h $SHA256.ComputeHash( ( h2i $sequences     ) )
        } else {
            $this.sha_prevouts      = ""
            $this.sha_amounts       = ""
            $this.sha_scriptpubkeys = ""
            $this.sha_sequences     = ""
        }
        if ( ( $sighashType -band 0x02 ) -eq 0 ) {
            $outputs = ""
            for ( $i = 0; $i -lt $tx.txouts.Length; $i++ ) {
                $outputs += $tx.txouts[$i].ToString()
            }
            $this.sha_outputs       = i2h $SHA256.ComputeHash( ( h2i $outputs ) )
        } else {
            $this.sha_outputs       = ""
        }
        $this.spend_type            = ( $ext_flag * 2 + $( if ( $annex ) { 1 } else { 0 } ) ).ToString( "x2" )
        if ( ( $sighashType -band 0x80 ) -ne 0 ) {
            $this.outpoint          = $tx.txins[$ntx].txid + $tx.txins[$ntx].index
            $this.amount            = UInt64toStr $values[$ntx]
            $this.scriptPubKey      = ConvertTo-CompactSizeHex $scripts[$ntx]
            $this.nSequence         = $tx.txins[$ntx].sequence
            $this.input_index       = ""
        } else {
            $this.outpoint          = ""
            $this.amount            = ""
            $this.scriptPubKey      = ""
            $this.nSequence         = ""
            $this.input_index       = UInt32toStr $ntx
        }
        if ( $annex ) {
            if ( $annex.Length % 2 -ne 0 -or $annex -notmatch '^50' ) { throw "invalid 'annex'" }
            $this.sha_annex         = i2h $SHA256.ComputeHash( ( h2i ( ConvertTo-CompactSizeHex $annex ) ) )
        } else {
            $this.sha_annex         = ""
        }
        if ( ( $sighashType -band 0x03 ) -eq 3 ) {
            $this.sha_single_output = i2h $SHA256.ComputeHash( ( h2i $tx.txouts[$ntx].ToString() ) )
        } else {
            $this.sha_single_output = ""
        }
        if ( $ext_flag -eq 1 ) {
            $this.tapleaf_hash      = $tapleaf_hash
            $this.key_version       = "00"
            $this.codesep_pos       = "ffffffff"
        } else {
            $this.tapleaf_hash      = ""
            $this.key_version       = ""
            $this.codesep_pos       = ""
        }
    }
}

class DER {
    [string]$type
    [string]$length
    [string]$type_r
    [string]$length_r
    [string]$value_r
    [string]$type_s
    [string]$length_s
    [string]$value_s
    DER ( [string]$r, [string]$s ) {
        if ( $r.Length % 2 -ne 0 ) { throw "invalid hex string length (r)" }
        if ( $s.Length % 2 -ne 0 ) { throw "invalid hex string length (s)" }
        $this.type        = "30"
        $this.length      = ( [int]( $r.Length / 2 ) + [int]( $s.Length / 2 ) + 4 ).ToString( "x2" ) 
        $this.type_r      = "02"
        $this.length_r    = ( [int]( $r.Length / 2 ) ).ToString( "x2" )
        $this.value_r     = $r
        $this.type_s      = "02"
        $this.length_s    = ( [int]( $s.Length / 2 ) ).ToString( "x2" )
        $this.value_s     = $s
    }
}

Update-TypeData -TypeName "TXin"      -MemberType "ScriptMethod" -MemberName "ToString" -Force -Value {
    return $this.PSObject.Properties.Value -join ""
}
Update-TypeData -TypeName "TXout"     -MemberType "ScriptMethod" -MemberName "ToString" -Force -Value {
    return $this.PSObject.Properties.Value -join ""
}
Update-TypeData -TypeName "Witness"   -MemberType "ScriptMethod" -MemberName "ToString" -Force -Value {
    return $this.PSObject.Properties.Value -join ""
}
Update-TypeData -TypeName "TX"      -MemberType "ScriptMethod" -MemberName "ToString" -Force -Value {
    return $this.PSObject.Properties.Value -join ""
}
Update-TypeData -TypeName "TXS"       -MemberType "ScriptMethod" -MemberName "ToString" -Force -Value {
    return $this.PSObject.Properties.Value -join ""
}
Update-TypeData -TypeName "SegwitMsg" -MemberType "ScriptMethod" -MemberName "ToString" -Force -Value {
    return $this.PSObject.Properties.Value -join ""
}
Update-TypeData -TypeName "TaprootMsg" -MemberType "ScriptMethod" -MemberName "ToString" -Force -Value {
    return $this.PSObject.Properties.Value -join ""
}
Update-TypeData -TypeName "DER"       -MemberType "ScriptMethod" -MemberName "ToString" -Force -Value {
    return $this.PSObject.Properties.Value -join ""
}

function deterministic_k( [bigint]$d, [bigint]$z ) {
# rfc6979's deterministic nonces
    $n  = [ECDSA]::Order
    $z  %= $n
    $da = $d.ToHexString64() | h2i
    $za = $z.ToHexString64() | h2i
    $wa = $da + $za
    $HMACSHA256 = New-Object Cryptography.HMACSHA256
    $HMACSHA256.Key = @(0x00) * 32
    $va = @(0x01) * 32
    $HMACSHA256.Key = $HMACSHA256.ComputeHash( $va + @(0x00) + $wa )
    $va = $HMACSHA256.ComputeHash( $va )
    $HMACSHA256.Key = $HMACSHA256.ComputeHash( $va + @(0x01) + $wa )
    while ( $true ) {
        $va = $HMACSHA256.ComputeHash( $HMACSHA256.ComputeHash( $va ) )
        $k  = [bigint]::new( $va[31..0] + @(0x00) )
        if ( $k -gt [bigint]::Zero -and $k -lt $n ) {
            return $k
        }
        $HMACSHA256.Key = $HMACSHA256.ComputeHash( $va + @(0x00) )
    }
}

function EcdsaSig {
    param( [string]$privateKey, 
           [string]$serializedTX, 
           [byte]$sighashType,
           [bool]$deterministic = $true
    )
    $n   = [ECDSA]::Order
    $G   = [ECDSA]::new()
    $msg = Hash256 $serializedTX
    $z   = [bigint]::Parse( "0" + $msg, "AllowHexSpecifier" )
    $d   = [bigint]::Parse( "0" + $privateKey, "AllowHexSpecifier" )
    if ( $d.IsZero -or $d -ge $n ) { throw "invalid private key" }
    if ( $deterministic ) {
        $k = deterministic_k $d $z
    } else {
        $buffer = [byte[]]::new( 32 )
        while( $true ) {
            [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes( $buffer )
            $rnd = i2h $buffer
            $k = [bigint]::Parse( "0" + $rnd, "AllowHexSpecifier" )
            if ( $k -gt [bigint]::Zero -and $k -lt $n ) {
                break
            }
        }
    }
    $kG  = $G * $k
    if ( $kG -eq $null ) { throw "arithmetic error" }
    $r   = $kG.X                                            % $n
    if ( $r.IsZero ) { throw "invalid ECDSA nonce result (r = 0)" }
    $s   = ( ( $z + $d * $r ) * [ECDSA]::ModInv( $k, $n ) ) % $n
    if ( $s.IsZero ) { throw "invalid ECDSA nonce result (s = 0)" }
    if ( $s -gt $n / 2 ) { $s = $n - $s }
    $r_h = $r.ToString( "x" ) -replace '^(.(?:..)*)$', '0$1'
    $s_h = $s.ToString( "x" ) -replace '^(.(?:..)*)$', '0$1'
    $sig = [DER]::new( $r_h, $s_h )
    return $sig.ToString() + $sighashType.ToString( "x2" )
}

function HashTR( [string]$tag_string, [string]$hex_string ) {    # Tagged hash function for Schnorr Signature
    if ( $tag_string -eq "" ) { throw "'tag_string' is empty" }
    if ( $hex_string -eq "" ) { throw "'hex_string' is empty" }
    if ( $hex_string -notmatch '^(?:[0-9a-f]{2})+$' ) { throw "invalid hex string" }
    $SHA256 = New-Object Cryptography.SHA256CryptoServiceProvider
    $tag  = $SHA256.ComputeHash( [Text.Encoding]::UTF8.GetBytes( $tag_string ) )
    $hash = i2h $SHA256.ComputeHash( $tag * 2 + ( h2i $hex_string ) )
    return $hash
}

function SchnorrSig ( [string]$privateKey, [string]$serializedTX, [byte]$sighashType ) {
    $n    = [ECDSA]::Order
    $G    = [ECDSA]::new()
    $d    = [bigint]::Parse( "0" + $privateKey, "AllowHexSpecifier" )
    if ( $d.IsZero -or $d -ge $n ) { throw "invalid private key" }
    $P    = $G * $d
    if ( $P -eq $null ) { throw "arithmetic error" }
    if ( -not $P.Y.IsEven ) { $d = $n - $d }
    $d_h  = $d.ToHexString64()
    $d_b  = h2i $d_h
    $buffer = [byte[]]::new( 32 )
    [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes( $buffer )
    $a_h  = i2h $buffer
    $ha_h = HashTR "BIP0340/aux" $a_h
    $ha_b = h2i $ha_h
    $t_h  = ( 0..31 | % { ( $d_b[$_] -bxor $ha_b[$_] ).ToString( "x2" ) } ) -join ""
    $p_h  = $P.X.ToHexString64()
    $msg  = HashTR "TapSighash" $serializedTX
    $rnd  = HashTR "BIP0340/nonce" ( $t_h + $p_h + $msg )
    $k    = [bigint]::Parse( "0" + $rnd, "AllowHexSpecifier" ) % $n
    if ( $k.IsZero ) { throw "You are unlucky!" }
    $R    = $G * $k
    if ( $R -eq $null ) { throw "arithmetic error" }
    if ( -not $R.Y.IsEven ) { $k = $n - $k }
    $r_h  = $R.X.ToHexString64()
    $e_h  = HashTR "BIP0340/challenge" ( $r_h + $p_h + $msg )
    $e    = [bigint]::Parse( "0" + $e_h, "AllowHexSpecifier" ) % $n
    $s    = ( $k + $e * $d ) % $n
    $s_h  = $s.ToHexString64()
    $sig  = $r_h + $s_h
    if ( $sighashType -and $sighashType -ne 0x00 ) { $sig += $sighashType.ToString( "x2" ) }
    return $sig
}

function GetAddressP2TR-SP {
    param( [Parameter(ValueFromPipeline=$True)][string]$publicKey, [Alias("t")][switch]$Testnet )
# Taproot address for a single-key script path spend.
# Internal key 0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0 ( = SHA256( G ) ) is used as an unspendable key path.
    AssertCompressedPublicKey $publicKey
    $internalKey = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
    $x           = [bigint]::Parse( "0" + $internalKey, "AllowHexSpecifier" )
    $H           = [ECDSA]::new( $x )  # lift_x( x )
    $G           = [ECDSA]::new()
    $leafVersion = "c0"
    $script      = "20" + $publicKey.Substring( 2 ) + "ac"  # PUSH(32byte publickey) + OP_CHECKSIG
    $tapLeaf     = HashTR "TapLeaf"  ( $leafVersion + ( ConvertTo-CompactSizeHex $script ) )
    $tapTweak    = HashTR "TapTweak" ( $internalKey + $tapLeaf )
    $t           = [bigint]::Parse( "0" + $tapTweak, "AllowHexSpecifier" )
    if ( $t -ge [ECDSA]::Order ) { throw "You are unlucky!" }
    $Q           = $H + $G * $t
    if ( $Q -eq $null -or $Q.Err ) { throw "The resulting address is invalid." }
    $outputKey   = $Q.X.ToHexString64()
    $hrp = if ( -not $Testnet ) { "bc" } else { "tb" }
    return ( Bech32_Encode $outputKey $hrp $true 1 )
}

function GetBalance {
    param( [Parameter(ValueFromPipeline=$True)][string]$addr )
    $addr = NormalizeBitcoinAddress $addr
    if ( $addr -cmatch '^[xyzYZ]prv' ) { return }
    if ( $addr -cmatch '^([13]|bc1)' ) {
        $addr = AssertBitcoinAddress $addr
        $chain   = "main"
    } elseif ( $addr -cmatch '^([2mn]|tb1)' ) {
        $addr = AssertBitcoinAddress $addr
        $chain   = "test3"
    } elseif ( $addr -cmatch '^[xyzYZtuvUV]pub' ) {
        $serialized = Base58Check_Decode $addr
        $version = if ( $serialized.Length -ge 8 ) { $serialized.Substring( 0, 8 ) } else { "" }
        $mainnetVersions = @("0295b43f","02aa7ed3","0488b21e","049d7cb2","04b24746")
        $testnetVersions = @("024289ef","02575483","043587cf","044a5262","045f1cf6")
        if ( $serialized.Length -ne 156 -or $version -notin ( $mainnetVersions + $testnetVersions ) ) {
            throw "invalid extended public key"
        }
        $chain = if ( $version -in $mainnetVersions ) { "main" } else { "test3" }
    } else {
        throw "invalid address"
    }
    $uri1 = "https://blockchain.info/balance?active=" + $addr
    $uri2 = "https://api.blockcypher.com/v1/btc/$chain/addrs/$addr/balance"
    try { return ( Invoke-RestMethod -Uri $uri1 -TimeoutSec 15 -ErrorAction Stop )."$addr"                                             } catch {}
    try { return ( Invoke-RestMethod -Uri $uri2 -TimeoutSec 15 -ErrorAction Stop | Select-Object final_balance, n_tx, total_received ) } catch {}
    throw "failed to get the balance"
}

function Invoke-RestMethodWithRetry {
    param ( [string]$Uri,
            [UInt32]$RetryCount = 5,
            [ValidateRange(1,300)][UInt32]$TimeoutSec = 15
          )

    for ( [UInt32]$attempt = 0; $attempt -le $RetryCount; $attempt++ ) {
        try {
            $value = Invoke-RestMethod -Uri $Uri -TimeoutSec $TimeoutSec -ErrorAction Stop
            return [pscustomobject]@{ Succeeded = $true; Value = $value }
        } catch {
            if ( $attempt -lt $RetryCount ) { Start-Sleep -Milliseconds 500 }
        }
    }
    return [pscustomobject]@{ Succeeded = $false; Value = $null }
}

function ConvertAddressToScriptPubKey {
    param ( [string]$addr )
    $addr = AssertBitcoinAddress $addr
    if ( $addr -cmatch '^[123mn]' ) {
        $decoded = Base58Address_Decode $addr
        $prefix  = $decoded.Substring( 0, 2 )
        $hash    = $decoded.Substring( 2 )
        if ( $prefix -in @( "00", "6f" ) ) {
            return "76a914" + $hash + "88ac"
        } else {
            return "a914" + $hash + "87"
        }
    }
    $isTaproot = $addr -cmatch '^(bc|tb)1p'
    $program   = Bech32_Decode $addr $isTaproot
    if ( $isTaproot ) {
        return "5120" + $program
    } elseif ( $program.Length -eq 40 ) {
        return "0014" + $program
    } else {
        return "0020" + $program
    }
}

function GetUTXO {
    param ( [Parameter(ValueFromPipeline=$True)][string]$addr )
    $addr = AssertBitcoinAddress $addr
    if ( $addr -cmatch '^([13]|bc1)' ) {
        $network = ""
    } elseif ( $addr -cmatch '^([2mn]|tb1)' ) {
        $network = "testnet"
    } else {
        throw "invalid address"
    }
    if ( $network ) {
        $uri = "https://mempool.space/$network/api/address/$addr/utxo"
    } else {
        $uri = "https://mempool.space/api/address/$addr/utxo"
    }
    $result = Invoke-RestMethodWithRetry $uri
    if ( -not $result.Succeeded ) { throw "failed to get utxo info from mempool.space." }
    $response = @( $result.Value )
    $scriptPubKey = ConvertAddressToScriptPubKey $addr
    $value = @{ Expression = { $_.value             }; Descending = $true  }
    $btime = @{ Expression = { $_.status.block_time }; Descending = $false }
    $utxo  = @( 
        $response | Where-Object { $_.status.confirmed }            `
                  | Sort-Object $value, $btime                      `
                  | Select-Object txid, vout, value, script
    )
    $utxo | % { $_.script = $scriptPubKey }
    return $utxo
}

function AssertLegacySource {
    param( [string]$address,
           [string]$publicKey,
           [string]$redeemScript
    )
    $actual = ( Base58Address_Decode $address ).Substring( 2 )
    $expected = if ( $address -cmatch '^[1mn]' ) {
        Hash160 $publicKey
    } else {
        Hash160 $redeemScript
    }
    if ( $actual -cne $expected ) {
        throw "private key or redeem script does not match 'addressFrom'"
    }
}

function AssertSegwitSource {
    param( [string]$address,
           [string]$publicKey,
           [string]$witnessScript
    )
    $address = NormalizeBitcoinAddress $address
    $pubkeyHash = Hash160 $publicKey
    if ( $witnessScript ) {
        $SHA256 = New-Object Cryptography.SHA256CryptoServiceProvider
        $witnessProgram = "0020" + ( i2h $SHA256.ComputeHash( ( h2i $witnessScript ) ) )
    } else {
        $witnessProgram = "0014" + $pubkeyHash
    }
    if ( $address -cmatch '^[23]' ) {
        $actual = ( Base58Address_Decode $address ).Substring( 2 )
        $expected = Hash160 $witnessProgram
    } else {
        $actual = Bech32_Decode $address $false
        $expected = $witnessProgram.Substring( 4 )
    }
    if ( $actual -cne $expected ) {
        throw "private key or witness script does not match 'addressFrom'"
    }
}

function AssertTaprootKeySource {
    param( [string]$address,
           [string]$publicKey
    )
    $address = NormalizeBitcoinAddress $address
    $testnet = $address -cmatch '^tb1p'
    $expected = GetAddressP2TR $publicKey -Testnet:$testnet
    if ( $address -ine $expected ) {
        throw "private key does not match 'addressFrom'"
    }
}

#===================================================================================================================================
function RawTXfromLegacyAddress {
    param ( [string]$wif, 
            [string]$addressFrom, 
            [string]$addressTo, 
            [UInt64]$amount, 
            [UInt64]$fee,
            [string]$redeemScript  = "",
            [string]$addressChange = "",
            [string]$memo          = "",
            [switch]$AllowDustToFee
          )

    $addressFrom = NormalizeBitcoinAddress $addressFrom
    $addressTo = NormalizeBitcoinAddress $addressTo
    if ( $addressChange ) { $addressChange = NormalizeBitcoinAddress $addressChange }

    if ( $addressTo -cmatch '^script:' ) {
        $scriptHash = Hash160 $addressTo.Substring( 7 )
        if ( $wif -cmatch '^[5KL]' ) {
            $addressTo = Base58Check_Encode ( "05" + $scriptHash )
        } else {
            $addressTo = Base58Check_Encode ( "c4" + $scriptHash )
        }
        Write-Host
        Write-Host "addressTo: $addressTo " -ForegroundColor Green
        Write-Host
    }

    if ( $wif -cmatch '^[5KL]' -and $addressFrom -cnotmatch '^[13]' ) { 
        throw "inconsistent networks between 'WIF' and 'addressFrom'" 
    } elseif ( $wif -cmatch '^[9c]'  -and $addressFrom -cnotmatch '^[2mn]' ) { 
        throw "inconsistent networks between'WIF' and 'addressFrom'"
    } elseif ( $wif -cnotmatch '^[59KLc]' ) {
        throw "invalid 'privateKey'"
    } elseif ( $addressFrom -cnotmatch '^[123mn]' ) {
        throw "invalid 'addressFrom'"
    }
    if ( $addressFrom -cmatch '^[13]'  -and $addressTo -cnotmatch '^([13]|bc1)' -or
         $addressFrom -cmatch '^[2mn]' -and $addressTo -cnotmatch '^([2mn]|tb1)' ) {
         throw "inconsistent networks between 'WIF/addressFrom' and 'addressTo'"
    } elseif ( $addressTo -cnotmatch '^([123mn]|bc1|tb1)' ) {
         throw "invalid 'addressTo'"
    }
    if ( $addressChange ) {
        if ( $addressFrom -cmatch '^[13]'  -and $addressChange -cnotmatch '^([13]|bc1)' -or
             $addressFrom -cmatch '^[2mn]' -and $addressChange -cnotmatch '^([2mn]|tb1)' ) {
            throw "inconsistent networks between 'WIF/addressFrom/addressTo' and 'addressChange'"
        } elseif ( $addressChange -cnotmatch '^([123mn]|bc1|tb1)' ) {
             throw "invalid 'addressChange'"
        }
    } else {
        $addressChange = $addressFrom
    }

    $privateKey_in = ( DecodeWIF $wif ).PrivateKey
    $publicKey_in  = GetPublicKeyFromWIF $wif
    if ( $addressFrom -cmatch '^[1mn]' ) {
        $pubkeyHash_in   = ( Base58Address_Decode $addressFrom ).Substring( 2 )
        $scriptPubKey_in = "76a914" + $pubkeyHash_in + "88ac"              # OP_DUP OP_HASH160 PUSH(pubkeyHash) OP_EQUALVERIFY OP_CHECKSIG
        if ( $redeemScript ) {
            Write-Host "'redeemScript' is ignored" -ForegroundColor Yellow
        }
    } elseif ( $addressFrom -cmatch '^[23]' ) {
        if ( -not $redeemScript -or $redeemScript -eq "single" ) {
            Write-Host "PublicKey isn't specified. Assuming 'PUSH(pubic key) OP_CHCKSIG'" -ForegroundColor Yellow
            $redeemScript = ( Push $publicKey_in ) + "ac"                  # PUSH(pubkey) OP_CHECKSIG
        }
    }
    AssertLegacySource $addressFrom $publicKey_in $redeemScript

    $utxo = @( GetUTXO $addressFrom )

    [UInt64]$sum = 0
    $txins_e = @(
        for ( $i=0; $i -lt $utxo.Length; $i++ ) {
            [TXin]::new( $utxo[$i].txid, $utxo[$i].vout )
            $sum += $utxo[$i].value
            if ( $sum -ge $amount + $fee ) { break }
        }
    )
    if ( $sum -lt $amount + $fee ) {
        throw "insufficient balance"
    }

    if ( $addressTo -cmatch '^[1mn]' ) {
        $pubkeyHash_out0   = ( Base58Address_Decode $addressTo ).Substring( 2 )
        $scriptPubKey_out0 = "76a914" + $pubkeyHash_out0 + "88ac"          # OP_DUP OP_HASH160 PUSH(pubkeyHash) OP_EQUALVERIFY OP_CHECKSIG
    } elseif ( $addressTo -cmatch '^[23]' ) { 
        $scriptHash_out0   = ( Base58Address_Decode $addressTo ).Substring( 2 )
        $scriptPubKey_out0 = "a914" + $scriptHash_out0 + "87"              # OP_HASH160 PUSH(scriptHash) OP_EQUAL
    } elseif ( $addressTo -cmatch '^(bc1|tb1)' ) {
        $isTaproot = $addressTo -cmatch '^(bc|tb)1p'
        $hash_out = Bech32_Decode $addressTo $isTaproot
        if ( $hash_out.Length -eq 40 ) {
            $pubkeyHash_out0 = $hash_out
            $scriptPubKey_out0 = "0014" + $pubkeyHash_out0                 # OP_0 PUSH(pubkeyHash)
        } elseif ( $hash_out.Length -eq 64 ) {
            if ( $isTaproot ) {
                $outputKey_out0    = $hash_out
                $scriptPubKey_out0 = "5120" + $outputKey_out0              # OP_1 PUSH(outputKey) for taproot        ( segwit ver 1 )
            } else {
                $scriptHash_out0   = $hash_out
                $scriptPubKey_out0 = "0020" + $scriptHash_out0             # OP_0 PUSH(scriptHash) for native segwit ( segwit ver 0 )
            }
        } else {
            throw "invalid hash length (addressTo)"
        }
    }
    if ( $addressChange -cmatch '^[1mn]' ) {
        $pubkeyHash_out1   = ( Base58Address_Decode $addressChange ).Substring( 2 )
        $scriptPubKey_out1 = "76a914" + $pubkeyHash_out1 + "88ac"
    } elseif ( $addressChange -cmatch '^[23]' ) {
        $scriptHash_out1   = ( Base58Address_Decode $addressChange ).Substring( 2 )
        $scriptPubKey_out1 = "a914" + $scriptHash_out1 + "87"
    } elseif ( $addressChange -cmatch '^(bc1|tb1)' ) { 
        $isTaproot = $addressChange -cmatch '^(bc|tb)1p'
        $hash_out = Bech32_Decode $addressChange $isTaproot
        if ( $hash_out.Length -eq 40 ) {
            $pubkeyHash_out1 = $hash_out
            $scriptPubKey_out1 = "0014" + $pubkeyHash_out1
        } elseif ( $hash_out.Length -eq 64 ) {
            if ( $isTaproot ) {
                $outputKey_out1    = $hash_out
                $scriptPubKey_out1 = "5120" + $outputKey_out1
            } else {
                $scriptHash_out1   = $hash_out
                $scriptPubKey_out1 = "0020" + $scriptHash_out1
            }
        } else {
            throw "invalid hash length (addressChange)"
        }
    }

    AssertPaymentAmount $amount $fee $scriptPubKey_out0
    $txout0 = [TXout]::new( $amount, $scriptPubKey_out0 )
    $txouts = @( $txout0 )

    [UInt64]$change = $sum - $amount - $fee
    [UInt64]$dustThreshold = GetDustThreshold $scriptPubKey_out1
    if ( $change -gt 0 -and $change -lt $dustThreshold -and -not $AllowDustToFee ) {
        throw "change ($change sat) is below the dust threshold ($dustThreshold sat); use -AllowDustToFee to add it to the fee"
    }
    if ( $change -ge $dustThreshold ) {
        $txout1 = [TXout]::new( $change, $scriptPubKey_out1 )
        $txouts += $txout1
    }
    if ( $memo ) {
        $bytes = [Text.Encoding]::UTF8.GetBytes( $memo )
        $num   = $bytes.Length
        if ( $num -gt 40 ) { throw "too long 'memo'" }
        $scriptPubKey_out2 = "6a" + ( Push ( i2h $bytes ) )   # 6a: OP_RETURN
        $txout2 = [TXout]::new( 0, $scriptPubKey_out2 )
        $txouts += $txout2
    }

    $sighashType = 0x01       # SIGHASH_ALL

    $txins = @(
        for ( $i=0; $i -lt $txins_e.Length; $i++ ) {
            $txins_t      = [TXin[]]$txins_e.Clone()
            if ( $addressFrom -cmatch '^[1mn]' ) {
                $txins_t[$i]  = [TXin]::new( $utxo[$i].txid, $utxo[$i].vout, $scriptPubKey_in )
                $serializedTX = [TX]::new( $txins_t, $txouts ).ToString() + ( UInt32toStr $sighashType )
                $signature    = EcdsaSig $privateKey_in $serializedTX $sighashType
                $scriptSig = ( Push $signature ) + ( Push $publicKey_in )
            } elseif ( $addressFrom -cmatch '^[23]' ) {
                $txins_t[$i]  = [TXin]::new( $utxo[$i].txid, $utxo[$i].vout, $redeemScript )
                $serializedTX = [TX]::new( $txins_t, $txouts ).ToString() + ( UInt32toStr $sighashType )
                $signature    = EcdsaSig $privateKey_in $serializedTX $sighashType
                $scriptSig = ( Push $signature ) + ( Push $redeemScript )
            }
            [TXin]::new( $utxo[$i].txid, $utxo[$i].vout, $scriptSig )
        }
    )

    $tx = [TX]::new( $txins, $txouts ).ToString()
    return $tx
}

#===================================================================================================================================
function RawTXfromSegwitAddress {
    param ( [string]$wif, 
            [string]$addressFrom, 
            [string]$addressTo, 
            [UInt64]$amount, 
            [UInt64]$fee,
            [string]$witnessScript = "",
            [string]$addressChange = "",
            [string]$memo          = "",
            [switch]$AllowDustToFee
          )

    $addressFrom = NormalizeBitcoinAddress $addressFrom
    $addressTo = NormalizeBitcoinAddress $addressTo
    if ( $addressChange ) { $addressChange = NormalizeBitcoinAddress $addressChange }

    $SHA256 = New-Object Cryptography.SHA256CryptoServiceProvider

    if ( $addressTo -cmatch '^script:' ) {
        $scriptHash = i2h $SHA256.ComputeHash( ( h2i $addressTo.Substring( 7 ) ) )
        if ( $wif -cmatch '^[KL]' ) {
            $hrp = "bc"
        } else {
            $hrp = "tb"
        }
        $addressTo = Bech32_Encode $scriptHash $hrp $false 0
        Write-Host
        Write-Host "addressTo: $addressTo " -ForegroundColor Green
        Write-Host
    }

    if ( $wif -cmatch '^[KL]' -and $addressFrom -cnotmatch '^(3|bc1)' ) { 
        throw "inconsistent networks between 'WIF' and 'addressFrom'"
    } elseif ( $wif -cmatch '^c'  -and $addressFrom -cnotmatch '^(2|tb1)' ) { 
        throw "inconsistent networks between 'WIF' and 'addressFrom'"
    } elseif ( $wif -cnotmatch '^[KLc]' ) {
        throw "invalid 'WIF'"
    } elseif ( $addressFrom -cnotmatch '^([23]|bc1|tb1)' ) {
        throw "invalid 'addressFrom'"
    }
    if ( $addressFrom -cmatch '^(bc|tb)1p' ) { throw "Taproot address is not supported for 'addressFrom'" }
    if ( $addressFrom -cmatch '^(3|bc1)' -and $addressTo -cnotmatch '^([13]|bc1)' -or
         $addressFrom -cmatch '^(2|tb1)' -and $addressTo -cnotmatch '^([2mn]|tb1)' ) {
         throw "inconsistent networks between 'WIF/addressFrom' and 'addressTo'"
    } elseif ( $addressTo -cnotmatch '^([123mn]|bc1|tb1)' ) {
         throw "invalid 'addressTo'"
    }
    if ( $addressChange ) {
        if ( $addressFrom -cmatch '^(3|bc1)' -and $addressChange -cnotmatch '^([13]|bc1)' -or
             $addressFrom -cmatch '^(2|tb1)' -and $addressChange -cnotmatch '^([2mn]|tb1)' ) {
            throw "inconsistent networks between 'WIF/addressFrom/addressTo' and 'addressChange'"
        } elseif ( $addressChange -cnotmatch '^([123mn]|bc1|tb1)' ) {
             throw "invalid 'addressChange'"
        }
    } else {
        $addressChange = $addressFrom
    }

    $privateKey_in = ( DecodeWIF $wif -Compressed ).PrivateKey
    $publicKey_in  = GetPublicKey $privateKey_in
    $pubkeyHash_in = Hash160 $publicKey_in
    if ( $witnessScript -eq "single" ) {
        $witnessScript = "21" + $publicKey_in + "ac"                       # PUSH(pubkey) OP_CHECKSIG
    }
    AssertSegwitSource $addressFrom $publicKey_in $witnessScript

    if ( $addressFrom -cmatch '^[23]' ) {
        if ( $witnessScript ) {    # P2SH-P2WSH
            $scriptHash_in = i2h $SHA256.ComputeHash( ( h2i $witnessScript ) )
            $scriptSig  = "220020"   + $scriptHash_in                      # PUSH( OP_0 PUSH(scriptHash) )
            $scriptCode = ConvertTo-CompactSizeHex $witnessScript           # CompactSize(witnessScript)
        } else {                   # P2SH-P2WPKH
            $scriptSig  = "160014"   + $pubkeyHash_in                      # PUSH( OP_0 PUSH(pubkeyHash) )
            $scriptCode = "1976a914" + $pubkeyHash_in + "88ac"             # PUSH( OP_DUP OP_HASH160 PUSH(pubkeyHash) OP_EQUALVERIFY OP_CHECKSIG )
        }
    } elseif ( $addressFrom -cmatch '^(bc1|tb1)' ) {
        $hash_in = Bech32_Decode $addressFrom
        if ( ( $hash_in.Length -eq 40 -and $witnessScript -ne "" ) -or
             ( $hash_in.Length -eq 64 -and $witnessScript -eq "" )     ) {
            throw "inconsistent 'addressFrom' and 'witnessScript'"
        }
        $scriptSig = ""
        if ( $witnessScript ) {    # P2WSH
            $scriptCode = ConvertTo-CompactSizeHex $witnessScript           # CompactSize(witnessScript)
        } else {                   # P2WPKH
            $scriptCode = "1976a914" + $pubkeyHash_in + "88ac"             # PUSH( OP_DUP OP_HASH160 PUSH(pubkeyHash) OP_EQUALVERIFY OP_CHECKSIG )
        }
    }

    $utxo = @( GetUTXO $addressFrom )

    [UInt64]$sum = 0
    $txins = @(
        for ( $i=0; $i -lt $utxo.Length; $i++ ) {
            [TXin]::new( $utxo[$i].txid, $utxo[$i].vout, $scriptSig )
            $sum += $utxo[$i].value
            if ( $sum -ge $amount + $fee ) { break }
        }
    )
    if ( $sum -lt $amount + $fee ) {
        throw "Insufficient balance"
    }

    if ( $addressTo -cmatch '^[1mn]' ) {
        $pubkeyHash_out0   = ( Base58Address_Decode $addressTo ).Substring( 2 )
        $scriptPubKey_out0 = "76a914" + $pubkeyHash_out0 + "88ac"          # OP_DUP OP_HASH160 PUSH(pubkeyHash) OP_EQUALVERIFY OP_CHECKSIG
    } elseif ( $addressTo -cmatch '^[23]' ) { 
        $scriptHash_out0   = ( Base58Address_Decode $addressTo ).Substring( 2 )
        $scriptPubKey_out0 = "a914" + $scriptHash_out0 + "87"              # OP_HASH160 PUSH(scriptHash) OP_EQUAL
    } elseif ( $addressTo -cmatch '^(bc1|tb1)' ) {
        $isTaproot = $addressTo -cmatch '^(bc|tb)1p'
        $hash_out = Bech32_Decode $addressTo $isTaproot
        if ( $hash_out.Length -eq 40 ) {
            $pubkeyHash_out0 = $hash_out
            $scriptPubKey_out0 = "0014" + $pubkeyHash_out0                 # OP_0 PUSH(pubkeyHash)
        } elseif ( $hash_out.Length -eq 64 ) {
            if ( $isTaproot ) {
                $outputKey_out0    = $hash_out
                $scriptPubKey_out0 = "5120" + $outputKey_out0              # OP_1 PUSH(outputKey) for taproot        ( segwit ver 1 )
            } else {
                $scriptHash_out0   = $hash_out
                $scriptPubKey_out0 = "0020" + $scriptHash_out0             # OP_0 PUSH(scriptHash) for native segwit ( segwit ver 0 )
            }
        } else {
            throw "invalid hash length (addressTo)"
        }
    }
    if ( $addressChange -cmatch '^[1mn]' ) {
        $pubkeyHash_out1   = ( Base58Address_Decode $addressChange ).Substring( 2 )
        $scriptPubKey_out1 = "76a914" + $pubkeyHash_out1 + "88ac"
    } elseif ( $addressChange -cmatch '^[23]' ) {
        $scriptHash_out1   = ( Base58Address_Decode $addressChange ).Substring( 2 )
        $scriptPubKey_out1 = "a914" + $scriptHash_out1 + "87"
    } elseif ( $addressChange -cmatch '^(bc1|tb1)' ) { 
        $isTaproot = $addressChange -cmatch '^(bc|tb)1p'
        $hash_out = Bech32_Decode $addressChange $isTaproot
        if ( $hash_out.Length -eq 40 ) {
            $pubkeyHash_out1 = $hash_out
            $scriptPubKey_out1 = "0014" + $pubkeyHash_out1
        } elseif ( $hash_out.Length -eq 64 ) {
            if ( $isTaproot ) {
                $outputKey_out1    = $hash_out
                $scriptPubkey_out1 = "5120" + $outputKey_out1
            } else {
                $scriptHash_out1   = $hash_out
                $scriptPubKey_out1 = "0020" + $scriptHash_out1
            }
        } else {
            throw "invalid hash length (addressChange)"
        }
    }

    AssertPaymentAmount $amount $fee $scriptPubKey_out0
    $txout0 = [TXout]::new( $amount, $scriptPubKey_out0 )
    $txouts = @( $txout0 )

    [UInt64]$change = $sum - $amount - $fee
    [UInt64]$dustThreshold = GetDustThreshold $scriptPubKey_out1
    if ( $change -gt 0 -and $change -lt $dustThreshold -and -not $AllowDustToFee ) {
        throw "change ($change sat) is below the dust threshold ($dustThreshold sat); use -AllowDustToFee to add it to the fee"
    }
    if ( $change -ge $dustThreshold ) {
        $txout1 = [TXout]::new( $change, $scriptPubKey_out1 )
        $txouts += $txout1
    }
    if ( $memo ) {
        $bytes = [Text.Encoding]::UTF8.GetBytes( $memo )
        $num   = $bytes.Length
        if ( $num -gt 40 ) { throw "too long 'memo'" }
        $scriptPubKey_out2 = "6a" + ( Push ( i2h $bytes ) )   # 6a: OP_RETURN
        $txout2 = [TXout]::new( 0, $scriptPubKey_out2 )
        $txouts += $txout2
    }

    $sighashType = 0x01       # SIGHASH_ALL

    $witnesses = @(
        $tx_t = [TXS]::new( $txins, $txouts )
        for ( $i=0; $i -lt $txins.Length; $i++ ) {
            $serializedTX = [SegwitMsg]::new( $tx_t, $i, $scriptCode, $utxo[$i].value, $sighashType ).ToString()
            $signature    = EcdsaSig $privateKey_in $serializedTX $sighashType
            if ( $witnessScript ) {
                [Witness]::new( @( ( ConvertTo-CompactSizeHex $signature ), ( ConvertTo-CompactSizeHex $witnessScript ) ) )
            } else {
                [Witness]::new( @( ( ConvertTo-CompactSizeHex $signature ), ( ConvertTo-CompactSizeHex $publicKey_in  ) ) )
            }
        }
    )

    $tx = [TXS]::new( $txins, $txouts, $witnesses ).ToString()
    return $tx
}

#===================================================================================================================================
function RawTXfromTaprootAddress {
    param ( [string]$wif, 
            [string]$addressFrom, 
            [string]$addressTo, 
            [UInt64]$amount, 
            [UInt64]$fee,
            [string]$tapScript = "",
            [string]$addressChange = "",
            [string]$memo          = "",
            [switch]$AllowDustToFee
          )

    $addressFrom = NormalizeBitcoinAddress $addressFrom
    $addressTo = NormalizeBitcoinAddress $addressTo
    if ( $addressChange ) { $addressChange = NormalizeBitcoinAddress $addressChange }

    if ( $addressTo -cmatch '^script:' ) {
# Internal key 0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0 ( = SHA256( G ) ) is used as an unspendable key path.
        $internalKey = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
        $x           = [bigint]::Parse( "0" + $internalKey, "AllowHexSpecifier" )
        $H           = [ECDSA]::new( $x )  # lift_x( x )
        $G           = [ECDSA]::new()
        $leafVersion = "c0"
        $script      = $addressTo.Substring( 7 )
        $tapLeaf     = HashTR "TapLeaf"  ( $leafVersion + ( ConvertTo-CompactSizeHex $script ) )
        $tapTweak    = HashTR "TapTweak" ( $internalKey + $tapLeaf )
        $t           = [bigint]::Parse( "0" + $tapTweak, "AllowHexSpecifier" )
        if ( $t -ge [ECDSA]::Order ) { throw "You are unlucky!" }
        $Q           = $H + $G * $t
        if ( $Q -eq $null ) { throw "The resulting 'addressTo' is invalid." }
        $outputKey   = $Q.X.ToHexString64()
        $hrp = if ( $wif -cmatch '^[KL]' ) { "bc" } else { "tb" }
        $addressTo = Bech32_Encode $outputKey $hrp $true 1
        Write-Host
        Write-Host "addressTo: $addressTo " -ForegroundColor Green
        Write-Host
    }

    if ( $wif -cmatch '^[KL]' -and $addressFrom -cnotmatch '^bc1p' ) {
        throw "inconsistent networks between 'WIF' and 'addressFrom'"
    } elseif ( $wif -cmatch '^c'  -and $addressFrom -cnotmatch '^tb1p' ) { 
        throw "inconsistent networks between 'WIF' and 'addressFrom'"
    } elseif ( $wif -cnotmatch '^[KLc]' ) {
        throw "invalid 'WIF'"
    } elseif ( $addressFrom -cnotmatch '^(bc|tb)1p' ) {
        throw "invalid 'addressFrom'"
    }
    if ( $addressFrom -cmatch '^bc1p' -and $addressTo -cnotmatch '^([13]|bc1)' -or
         $addressFrom -cmatch '^tb1p' -and $addressTo -cnotmatch '^([2mn]|tb1)' ) {
         throw "inconsistent networks between 'WIF/addressFrom' and 'addressTo'"
    } elseif ( $addressTo -cnotmatch '^([123mn]|bc1|tb1)' ) {
         throw "invalid 'addressTo'"
    }
    if ( $addressChange ) {
        if ( $addressFrom -cmatch '^bc1p' -and $addressChange -cnotmatch '^([13]|bc1)' -or
             $addressFrom -cmatch '^tb1p' -and $addressChange -cnotmatch '^([2mn]|tb1)' ) {
            throw "inconsistent networks between 'WIF/addressFrom/addressTo' and 'addressChange'"
        } elseif ( $addressChange -cnotmatch '^([123mn]|bc1|tb1)' ) {
             throw "invalid 'addressChange'"
        }
    } else {
        $addressChange = $addressFrom
    }

    if ( -not $tapScript ) {
        $privateKey_in = ( DecodeWIF $wif -Compressed ).PrivateKey
        $publicKey_in  = GetPublicKey $privateKey_in
        AssertTaprootKeySource $addressFrom $publicKey_in
    }

    $utxo = @( GetUTXO $addressFrom )

    [UInt64]$sum = 0
    $txins = @(
        for ( $i=0; $i -lt $utxo.Length; $i++ ) {
            [TXin]::new( $utxo[$i].txid, $utxo[$i].vout )
            $sum += $utxo[$i].value
            if ( $sum -ge $amount + $fee ) { break }
        }
    )
    if ( $sum -lt $amount + $fee ) {
        throw "Insufficient balance"
    }

    if ( $addressTo -cmatch '^[1mn]' ) {
        $pubkeyHash_out0   = ( Base58Address_Decode $addressTo ).Substring( 2 )
        $scriptPubKey_out0 = "76a914" + $pubkeyHash_out0 + "88ac"          # OP_DUP OP_HASH160 PUSH(pubkeyHash) OP_EQUALVERIFY OP_CHECKSIG
    } elseif ( $addressTo -cmatch '^[23]' ) { 
        $scriptHash_out0   = ( Base58Address_Decode $addressTo ).Substring( 2 )
        $scriptPubKey_out0 = "a914" + $scriptHash_out0 + "87"              # OP_HASH160 PUSH(scriptHash) OP_EQUAL
    } elseif ( $addressTo -cmatch '^(bc1|tb1)' ) {
        $isTaproot = $addressTo -cmatch '^(bc|tb)1p'
        $hash_out = Bech32_Decode $addressTo $isTaproot
        if ( $hash_out.Length -eq 40 ) {
            $pubkeyHash_out0 = $hash_out
            $scriptPubKey_out0 = "0014" + $pubkeyHash_out0                 # OP_0 PUSH(pubkeyHash)
        } elseif ( $hash_out.Length -eq 64 ) {
            if ( $isTaproot ) {
                $outputKey_out0    = $hash_out
                $scriptPubKey_out0 = "5120" + $outputKey_out0              # OP_1 PUSH(outputKey) for taproot        ( segwit ver 1 )
            } else {
                $scriptHash_out0   = $hash_out
                $scriptPubKey_out0 = "0020" + $scriptHash_out0             # OP_0 PUSH(scriptHash) for native segwit ( segwit ver 0 )
            }
        } else {
            throw "invalid hash length (addressTo)"
        }
    }
    if ( $addressChange -cmatch '^[1mn]' ) {
        $pubkeyHash_out1   = ( Base58Address_Decode $addressChange ).Substring( 2 )
        $scriptPubKey_out1 = "76a914" + $pubkeyHash_out1 + "88ac"
    } elseif ( $addressChange -cmatch '^[23]' ) {
        $scriptHash_out1   = ( Base58Address_Decode $addressChange ).Substring( 2 )
        $scriptPubKey_out1 = "a914" + $scriptHash_out1 + "87"
    } elseif ( $addressChange -cmatch '^(bc1|tb1)' ) { 
        $isTaproot = $addressChange -cmatch '^(bc|tb)1p'
        $hash_out = Bech32_Decode $addressChange $isTaproot
        if ( $hash_out.Length -eq 40 ) {
            $pubkeyHash_out1 = $hash_out
            $scriptPubKey_out1 = "0014" + $pubkeyHash_out1
        } elseif ( $hash_out.Length -eq 64 ) {
            if ( $isTaproot ) {
                $outputKey_out1    = $hash_out
                $scriptPubKey_out1 = "5120" + $outputKey_out1
            } else {
                $scriptHash_out1   = $hash_out
                $scriptPubKey_out1 = "0020" + $scriptHash_out1
            }
        } else {
            throw "invalid hash length (addressChange)"
        }
    }

    AssertPaymentAmount $amount $fee $scriptPubKey_out0
    $txout0 = [TXout]::new( $amount, $scriptPubKey_out0 )
    $txouts = @( $txout0 )

    [UInt64]$change = $sum - $amount - $fee
    [UInt64]$dustThreshold = GetDustThreshold $scriptPubKey_out1
    if ( $change -gt 0 -and $change -lt $dustThreshold -and -not $AllowDustToFee ) {
        throw "change ($change sat) is below the dust threshold ($dustThreshold sat); use -AllowDustToFee to add it to the fee"
    }
    if ( $change -ge $dustThreshold ) {
        $txout1 = [TXout]::new( $change, $scriptPubKey_out1 )
        $txouts += $txout1
    }
    if ( $memo ) {
        $bytes = [Text.Encoding]::UTF8.GetBytes( $memo )
        $num   = $bytes.Length
        if ( $num -gt 40 ) { throw "too long 'memo'" }
        $scriptPubKey_out2 = "6a" + ( Push ( i2h $bytes ) )   # 6a: OP_RETURN
        $txout2 = [TXout]::new( 0, $scriptPubKey_out2 )
        $txouts += $txout2
    }

    if ( $tapScript ) {
        $privateKey_in = ( DecodeWIF $wif -Compressed ).PrivateKey
        if ( $tapScript -eq "single" ) {
            $publicKey_in  = ( GetPublicKey $privateKey_in ).Substring( 2 )
            $tapScript = "20" + $publicKey_in + "ac"                   # PUSH(32-byte pubkey) OP_CHECKSIG
        }

# Internal key 0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0 ( = SHA256( G ) ) is used as an unspendable key path.
        $internalKey  = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
        $leafVersion  = "c0"
        $tapleaf_hash = HashTR "TapLeaf" ( $leafVersion + ( ConvertTo-CompactSizeHex $tapScript ) )
        $tapTweak     = HashTR "TapTweak" ( $internalKey + $tapleaf_hash )
        $t            = [bigint]::Parse( "0" + $tapTweak, "AllowHexSpecifier" )
        if ( $t -ge [ECDSA]::Order ) { throw "You are unlucky!" }
        $H = [ECDSA]::new( [bigint]::Parse( "0" + $internalKey, "AllowHexSpecifier" ) )
        $Q = $H + [ECDSA]::new() * $t
        if ( $Q -eq $null ) { throw "The resulting 'addressFrom' is invalid." }
        if ( ( Bech32_Decode $addressFrom $true ) -cne $Q.X.ToHexString64() ) {
            throw "inconsistent 'addressFrom' and 'tapScript'"
        }
        $controlByte  = if ( $Q.Y.IsEven ) { "c0" } else { "c1" }
        $controlBlock = $controlByte + $internalKey
    } else {
        $twif = GetTweakedWIF $wif
        $privateKey_in = ( Base58Check_Decode $twif ).Substring( 2, 64 )
    }

    $sighashType = 0x00       # SIGHASH_DEFAULT

    $witnesses = @(
        $tx_t = [TXS]::new( $txins, $txouts )
        $selectedUtxo = $utxo[0..($txins.Length - 1)]
        [string[]]$scripts = $selectedUtxo | % { $_.script }
        [UInt64[]]$values  = $selectedUtxo | % { $_.value  }
        for ( $i=0; $i -lt $txins.Length; $i++ ) {
            if ( $tapScript ) {
                $serializedTX = "00" + [TaprootMsg]::new( $tx_t, $i, $scripts, $values, $sighashType, 1, "", $tapleaf_hash ).ToString()
                $signature    = SchnorrSig $privateKey_in $serializedTX $sighashType
                [Witness]::new( @( ( ConvertTo-CompactSizeHex $signature ), ( ConvertTo-CompactSizeHex $tapScript ), ( ConvertTo-CompactSizeHex $controlBlock ) ) )
            } else {
                $serializedTX = "00" + [TaprootMsg]::new( $tx_t, $i, $scripts, $values, $sighashType ).ToString()
                $signature    = SchnorrSig $privateKey_in $serializedTX $sighashType
                [Witness]::new( @( ( ConvertTo-CompactSizeHex $signature ) ) )
            }
        }
    )

    $tx = [TXS]::new( $txins, $txouts, $witnesses ).ToString()
    return $tx
}

#===================================================================================================================================
function NulldataTX {
    param ( [string]$wif, 
            [string]$addressFrom,  # Segwit v0 address
            [string]$text, 
            [UInt64]$fee,
            [string]$witnessScript = "",
            [string]$addressChange = "",
            [switch]$AllowDustToFee,
            [UInt32]$lockTime      = 0
          )
    $addressFrom = NormalizeBitcoinAddress $addressFrom
    if ( $addressChange ) { $addressChange = NormalizeBitcoinAddress $addressChange }

    $bytes = [Text.Encoding]::UTF8.GetBytes( $text )
    $num   = $bytes.Length
    if ( $num -gt 40 ) { throw "too long text" }
    $scriptPubKey_out0 = "6a" + ( Push ( i2h $bytes ) )       # 6a: OP_RETURN

    if ( $wif -cmatch '^[KL]' -and $addressFrom -cnotmatch '^(3|bc1)' ) { 
        throw "inconsistent networks between 'WIF' and 'addressFrom'"
    } elseif ( $wif -cmatch '^c'  -and $addressFrom -cnotmatch '^(2|tb1)' ) { 
        throw "inconsistent networks between 'WIF' and 'addressFrom'"
    } elseif ( $wif -cnotmatch '^[KLc]' ) {
        throw "invalid 'WIF'"
    } elseif ( $addressFrom -cnotmatch '^([23]|bc1|tb1)' ) {
        throw "invalid 'addressFrom'"
    }
    if ( $addressFrom -cmatch '^(bc|tb)1p' ) { throw "Taproot address is not supported for 'addressFrom'" }
    if ( $addressChange ) {
        if ( $addressFrom -cmatch '^(3|bc1)' -and $addressChange -cnotmatch '^([13]|bc1)' -or
             $addressFrom -cmatch '^(2|tb1)' -and $addressChange -cnotmatch '^([2mn]|tb1)' ) {
            throw "inconsistent networks between 'WIF/addressFrom/addressTo' and 'addressChange'"
        } elseif ( $addressChange -cnotmatch '^([123mn]|bc1|tb1)' ) {
             throw "invalid 'addressChange'"
        }
    } else {
        $addressChange = $addressFrom
    }

    $privateKey_in = ( DecodeWIF $wif -Compressed ).PrivateKey
    $publicKey_in  = GetPublicKey $privateKey_in
    $pubkeyHash_in = Hash160 $publicKey_in
    $SHA256 = New-Object Cryptography.SHA256CryptoServiceProvider
    if ( $witnessScript -eq "single" ) {
        $witnessScript = "21" + $publicKey_in + "ac"                       # PUSH(pubkey) OP_CHECKSIG
    }
    AssertSegwitSource $addressFrom $publicKey_in $witnessScript

    if ( $addressFrom -cmatch '^[23]' ) {
        if ( $witnessScript ) {    # P2SH-P2WSH
            $scriptHash_in = i2h $SHA256.ComputeHash( ( h2i $witnessScript ) )
            $scriptSig  = "220020"   + $scriptHash_in                      # PUSH( OP_0 PUSH(scriptHash) )
            $scriptCode = ConvertTo-CompactSizeHex $witnessScript           # CompactSize(witnessScript)
        } else {                   # P2SH-P2WPKH
            $scriptSig  = "160014"   + $pubkeyHash_in                      # PUSH( OP_0 PUSH(pubkeyHash) )
            $scriptCode = "1976a914" + $pubkeyHash_in + "88ac"             # PUSH( OP_DUP OP_HASH160 PUSH(pubkeyHash) OP_EQUALVERIFY OP_CHECKSIG )
        }
    } elseif ( $addressFrom -cmatch '^(bc1|tb1)' ) {
        $hash_in = Bech32_Decode $addressFrom
        if ( ( $hash_in.Length -eq 40 -and $witnessScript -ne "" ) -or
             ( $hash_in.Length -eq 64 -and $witnessScript -eq "" )     ) {
            throw "inconsistent 'addressFrom' and 'witnessScript'"
        }
        $scriptSig = ""
        if ( $witnessScript ) {    # P2WSH
            $scriptCode = ConvertTo-CompactSizeHex $witnessScript           # CompactSize(witnessScript)
        } else {                   # P2WPKH
            $scriptCode = "1976a914" + $pubkeyHash_in + "88ac"             # PUSH( OP_DUP OP_HASH160 PUSH(pubkeyHash) OP_EQUALVERIFY OP_CHECKSIG )
        }
    }

    $utxo = @( GetUTXO $addressFrom )

    # The fee will be adjusted up to a maximum of 5% less than the specified value.
    $minimumFee = [UInt64][Math]::Ceiling( [decimal]$fee * [decimal]0.95 )
    [UInt64]$sum = 0
    $txins = @(
        for ( $i=0; $i -lt $utxo.Length; $i++ ) {
            [TXin]::new( $utxo[$i].txid, $utxo[$i].vout, $scriptSig )
            $sum += $utxo[$i].value
            if ( $sum -ge $minimumFee ) { break }
        }
    )
    if ( $txins.Count -eq 0 -or $sum -eq 0 -or $sum -lt $minimumFee ) {
        throw "insufficient balance"
    }
    [UInt64]$change = if ( $sum -gt $fee ) { $sum - $fee } else { 0 }
    $createChange = $false
    if ( $change -gt 0 ) {
        if ( $addressChange -cmatch '^[1mn]' ) {
            $pubkeyHash_out1   = ( Base58Address_Decode $addressChange ).Substring( 2 )
            $scriptPubKey_out1 = "76a914" + $pubkeyHash_out1 + "88ac"      # OP_DUP OP_HASH160 PUSH(pubkeyHash) OP_EQUALVERIFY OP_CHECKSIG
        } elseif ( $addressChange -cmatch '^[23]' ) {
            $scriptHash_out1   = ( Base58Address_Decode $addressChange ).Substring( 2 )
            $scriptPubKey_out1 = "a914" + $scriptHash_out1 + "87"          # OP_HASH160 PUSH(scriptHash) OP_EQUAL
        } elseif ( $addressChange -cmatch '^(bc1|tb1)' ) { 
            $isTaproot = $addressChange -cmatch '^(bc|tb)1p'
            $hash_out = Bech32_Decode $addressChange $isTaproot
            if ( $hash_out.Length -eq 40 ) {
                $pubkeyHash_out1 = $hash_out
                $scriptPubKey_out1 = "0014" + $pubkeyHash_out1             # OP_0 PUSH(pubkeyHash)
            } elseif ( $hash_out.Length -eq 64 ) {
                if ( $isTaproot ) {
                    $outputKey_out1    = $hash_out
                    $scriptPubKey_out1 = "5120" + $outputKey_out1          # OP_1 PUSH(outputKey) for taproot        ( segwit ver 1 )
                } else {
                    $scriptHash_out1   = $hash_out
                    $scriptPubKey_out1 = "0020" + $scriptHash_out1         # OP_0 PUSH(scriptHash) for native segwit ( segwit ver 0 )
                }
            } else {
                throw "invalid hash length (addressChange)"
            }
        }
        [UInt64]$dustThreshold = GetDustThreshold $scriptPubKey_out1
        if ( $change -lt $dustThreshold -and -not $AllowDustToFee ) {
            throw "change ($change sat) is below the dust threshold ($dustThreshold sat); use -AllowDustToFee to add it to the fee"
        }
        $createChange = $change -ge $dustThreshold
    }
    if ( $createChange ) {
        $txout0 = [TXout]::new( 0          , $scriptPubKey_out0 )
        $txout1 = [TXout]::new( $change, $scriptPubKey_out1 )
        $txouts = @( $txout0, $txout1 )
    } else {
        if ( $sum -lt $fee ) { Write-Host "The fee has been changed to $($sum)." -ForegroundColor Yellow }
        $txout0 = [TXout]::new( 0, $scriptPubKey_out0 )
        $txouts = @( $txout0 )
    }

    $sighashType = 0x01       # SIGHASH_ALL

    $witnesses = @(
        $tx_t = [TXS]::new( $txins, $txouts )
        for ( $i=0; $i -lt $txins.Length; $i++ ) {
            $serializedTX = [SegwitMsg]::new( $tx_t, $i, $scriptCode, $utxo[$i].value, $sighashType ).ToString()
            $signature    = EcdsaSig $privateKey_in $serializedTX $sighashType
            if ( $witnessScript ) {
                [Witness]::new( @( ( ConvertTo-CompactSizeHex $signature ), ( ConvertTo-CompactSizeHex $witnessScript ) ) )
            } else {
                [Witness]::new( @( ( ConvertTo-CompactSizeHex $signature ), ( ConvertTo-CompactSizeHex $publicKey_in  ) ) )
            }
        }
    )

    $tx = [TXS]::new( $txins, $txouts, $witnesses ).ToString()
    return $tx
}

#===================================================================================================================================
function CLTVScript {
    param( [string]$datetime, [string]$publicKey, [Alias("t")][switch]$Testnet )
    AssertCompressedPublicKey $publicKey
    $SHA256 = New-Object Cryptography.SHA256CryptoServiceProvider
    $unixTime = [UInt32]( Get-Date -Date $datetime -UFormat "%s" )
    if ( $unixTime -lt 500000000 ) {
        throw "'datetime' must be after or the same as '1985/11/05 9:53:20'JST"
    }
    $lockTime = UInt32toStr ( $unixTime )

    $script   = ( Push $lockTime ) + "b175" + ( Push $publicKey ) + "ac"   # PUSH(expiry time) OP_CHECKLOCKTIMEVERIFY OP_DROP PUSH(public key) OP_CHECKSIG
    $scriptHash_P2SH  = Hash160 $script
    $scriptHash_P2WSH = i2h $SHA256.ComputeHash( ( h2i $script ) )

    $scriptPubKey_P2SH      = "a914" + $scriptHash_P2SH + "87"             # OP_HASH160 PUSH(redeemScript hash) OP_EQUAL
    $scriptPubKey_P2WSH     = "0020" + $scriptHash_P2WSH                   # OP_0 PUSH(witnessScript hash)

    $redeemScript_P2SHP2WSH = $scriptPubKey_P2WSH
    $scriptHash_P2SHP2WSH   = Hash160 $redeemScript_P2SHP2WSH
    $scriptPubKey_P2SHP2WSH = "a914" + $scriptHash_P2SHP2WSH + "87"        # OP_HASH160 PUSH(redeemScript hash) OP_EQUAL

    if ( -not $Testnet ) {
        $address_P2SH      = Base58Check_Encode ( "05" + $scriptHash_P2SH      )
        $address_P2SHP2WSH = Base58Check_Encode ( "05" + $scriptHash_P2SHP2WSH )
        $address_P2WSH     = Bech32_Encode      $scriptHash_P2WSH "bc" $false 0
    } else {
        $address_P2SH      = Base58Check_Encode ( "c4" + $scriptHash_P2SH      )
        $address_P2SHP2WSH = Base58Check_Encode ( "c4" + $scriptHash_P2SHP2WSH )
        $address_P2WSH     = Bech32_Encode      $scriptHash_P2WSH "tb" $false 0
    }

    Write-Output "P2SH        scriptPubKey: $($scriptPubKey_P2SH)"
    Write-Output "                 address: $($address_P2SH)"
    Write-Output "P2SH-P2WSH  scriptPubKey: $($scriptPubKey_P2SHP2WSH)" 
    Write-Output "                 address: $($address_P2SHP2WSH)"
    Write-Output "P2WSH       scriptPubKey: $($scriptPubKey_P2WSH)"
    Write-Output "                 address: $($address_P2WSH)"
    Write-Output ""
    Write-Output "   redeem/witness script: $($script)"
}

#===================================================================================================================================
function SignMessage {
    param( [string]$wif,
           [string]$address,
           [string]$message,
             [bool]$deterministic = $true,
           [switch]$electrum = $false,
           [switch]$_taprootExtension = $false,
           [switch]$verbose = $false
    )
    $address = NormalizeBitcoinAddress $address

    $isEncodedWIF = $false
    if ( $wif -cmatch '^[0-9a-fA-F]{64}$' ) {
        AssertPrivateKey $wif
        $privateKey = $wif.ToLowerInvariant()
        $compressed = $true
    } else {
        try {
            $decodedWIF = Base58Check_Decode $wif
        } catch {
            throw "invalid WIF"
        }
        if ( $decodedWIF -cnotmatch '^(80|ef)[0-9a-f]{64}(01)?$' ) {
            throw "invalid WIF"
        }
        $isEncodedWIF = $true
        $wifTestnet   = $decodedWIF.StartsWith( "ef" )
        $privateKey   = $decodedWIF.Substring( 2, 64 )
        $compressed   = $decodedWIF.Length -eq 68
    }
    if ( $address -cmatch '^([13]|bc1)' ) {
        $Testnet = $false
    } elseif ( $address -cmatch '^([2mn]|tb1)' ) {
        $Testnet = $true
    } else {
        throw "invalid address"
    }
    if ( $isEncodedWIF -and $wifTestnet -ne $Testnet ) {
        throw "WIF and address network mismatch"
    }
    $n = [ECDSA]::Order
    $p = [ECDSA]::p
    $G = [ECDSA]::new()
    $msgPrefix = @( 0x18 ) + [Text.Encoding]::UTF8.GetBytes( "Bitcoin Signed Message:`n" )
    $msgBytes  = [Text.Encoding]::UTF8.GetBytes( $message )
    $msgMagic  = [Bitconverter]::ToString( $msgPrefix ).Replace( "-", "" ) `
               + ( VarInttoStr $msgBytes.Length )                          `
               + [Bitconverter]::ToString( $msgBytes  ).Replace( "-", "" )
    $msgHash   = Hash256 $msgMagic
    $z = [bigint]::Parse( "0" + $msgHash   , "AllowHexSpecifier" )
    $d = [bigint]::Parse( "0" + $privateKey, "AllowHexSpecifier" )
    if ( $d.IsZero -or $d -ge $n ) { throw "invalid private key" }
    if ( $deterministic ) {
        $k = deterministic_k $d $z
    } else {
        $buffer = [byte[]]::new( 32 )
        while( $true ) {
            [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes( $buffer )
            $rnd = i2h $buffer
            $k = [bigint]::Parse( "0" + $rnd, "AllowHexSpecifier" )
            if ( $k -gt [bigint]::Zero -and $k -lt $n ) {
                break
            }
        }
    }
    $kG  = $G * $k
    if ( $kG -eq $null ) { throw "arithmetic error" }
    $r   = $kG.X                                            % $n
    if ( -not $r ) { throw "arithmetic error" }
    $s   = ( ( $z + $d * $r ) * [ECDSA]::ModInv( $k, $n ) ) % $n
    if ( -not $s ) { throw "arithmetic error" }
    if ( $s -gt $n / 2 ) { $s = $n - $s }
    $Rcand = @(
        $R0 = [ECDSA]::new( $r )
        $R0, [ECDSA]::new( $R0.X, ( $p - $R0.Y ) % $p )
        if ( $r + $n -lt $p ) {
            $R2 = [ECDSA]::new( $r + $n )
            $R2, [ECDSA]::new( $R2.X, ( $p - $R2.Y ) % $p )
        }
    )
    $publicKey = GetPublicKey $privateKey
    if ( $compressed ) {
        $recId = 4
    } else {
        $recId = 0
    }
    for ( $i = 0 ; $i -lt $Rcand.Length; $i++ ) {
        if ( -not $Rcand[$i].Err ) {
            $Q = ( ( $Rcand[$i] * $s ) + $G * ( (-$z) % $n ) ) * [ECDSA]::ModInv( $r, $n )
            if ( $publicKey.SubString(2, 64) -eq $Q.X.ToHexString64() ) {
                $recId += $i
                break
            }
         }
    }
    if ( $_taprootExtension ) {
        if ( $electrum ) { throw "incompatible message signature options" }
        if ( -not $compressed -or $address -cne ( GetAddressP2TR $publicKey -Testnet:$Testnet ) ) {
            throw "address mismatch"
        }
        # 43..46 is an existing psBitcoin extension. BIP137 ends at header 42.
        $recId += 39
    } elseif ( $electrum ) {
        if ( $compressed ) {
            $validAddresses = @(
                GetAddressP2PKH        $publicKey -Testnet:$Testnet
                GetAddressP2SH-P2WPKH  $publicKey -Testnet:$Testnet
                GetAddressP2WPKH       $publicKey -Testnet:$Testnet
            )
        } else {
            $validAddresses = @( GetAddressP2PKH ( GetPublicKey -uc $privateKey ) -Testnet:$Testnet )
        }
        if ( $validAddresses -cnotcontains $address ) { throw "address mismatch" }
        $recId += 27
    } elseif ( -not $compressed -and $address -ceq ( GetAddressP2PKH ( GetPublicKey -uc $privateKey ) -Testnet:$Testnet ) ) {
        $recId += 27
    } elseif ( $compressed -and $address -ceq ( GetAddressP2PKH       $publicKey -Testnet:$Testnet ) ) {
        $recId += 27
    } elseif ( $compressed -and $address -ceq ( GetAddressP2SH-P2WPKH $publicKey -Testnet:$Testnet ) ) {
        $recId += 31
    } elseif ( $compressed -and $address -ceq ( GetAddressP2WPKH      $publicKey -Testnet:$Testnet ) ) {
        $recId += 35
    } else {
        throw "address mismatch"
    }
    $r_h = $r.ToHexString64()
    $s_h = $s.ToHexString64()
    $sig = [Convert]::ToBase64String( ( $recId.ToString( "x2" ) + $r_h + $s_h | h2i ) )
    if ( $verbose ) {
        return "-----BEGIN BITCOIN SIGNED MESSAGE-----`n$message`n-----BEGIN BITCOIN SIGNATURE-----`n$address`n`n$sig`n-----END BITCOIN SIGNATURE-----"
    } else {
        return $sig
    }
}

function SignMessageP2TR {
    param( [string]$wif,
           [string]$address,
           [string]$message,
             [bool]$deterministic = $true,
           [switch]$verbose = $false
    )
    SignMessage $wif $address $message $deterministic -_taprootExtension -verbose:$verbose
}

function VerifyMessage {
    param( [string]$sig,
           [string]$address,
           [string]$message,
           [switch]$electrum = $false,
           [switch]$_taprootExtension = $false
    )
    $address = NormalizeBitcoinAddress $address

    $sig_h  = i2h ( [Convert]::FromBase64String( $sig ) )
    if ( $sig_h.Length -ne 130 ) {
        throw "invalid signature length"
    }
    $header = [byte]( "0x" + $sig_h.SubString(  0,  2 ) )
    $r_h    = $sig_h.SubString(  2, 64 )
    $s_h    = $sig_h.SubString( 66, 64 )
    if ( $address -cmatch '^([13]|bc1)' ) {
        $Testnet = $false
    } elseif ( $address -cmatch '^([2mn]|tb1)' ) {
        $Testnet = $true
    } else {
        throw "invalid address"
    }
    $n = [ECDSA]::Order
    $p = [ECDSA]::p
    $G = [ECDSA]::new()
    $msgPrefix = @( 0x18 ) + [Text.Encoding]::UTF8.GetBytes( "Bitcoin Signed Message:`n" )
    $msgBytes  = [Text.Encoding]::UTF8.GetBytes( $message )
    $msgMagic  = [Bitconverter]::ToString( $msgPrefix ).Replace( "-", "" ) `
               + ( VarInttoStr $msgBytes.Length )                          `
               + [Bitconverter]::ToString( $msgBytes  ).Replace( "-", "" )
    $msgHash   = Hash256 $msgMagic
    $z = [bigint]::Parse( "0" + $msgHash, "AllowHexSpecifier" )
    $r = [bigint]::Parse( "0" + $r_h    , "AllowHexSpecifier" )
    $s = [bigint]::Parse( "0" + $s_h    , "AllowHexSpecifier" )
    if ( $_taprootExtension ) {
        if ( $electrum -or $header -lt 43 -or $header -ge 47 ) { return $false }
    } elseif ( $header -lt 27 -or $header -ge 43 ) {
        return $false
    }
    if ( $r -le [bigint]::Zero -or $r -ge $n -or
         $s -le [bigint]::Zero -or $s -ge $n     ) { return $false }
    $recId = ( $header - 27 ) -band 0x03
    if ( ( $recId -band 0x02 ) -eq 0 ) {
        $x = $r
    } else {
        $x = $r + $n
    }
    if ( $x -ge $p ) { return $false }
    $yy = ( [bigint]::ModPow( $x, 3, $p ) + 7 ) % $p
    $ya = [bigint]::ModPow( $yy, ($p + 1)/4, $p )
    if ( $yy -ne ( $ya * $ya ) % $p ) {
        return $false
    }
    if ( (      $ya.IsEven -and ( $recId -band 0x01 ) -eq 0 ) -or `
         ( -not $ya.IsEven -and ( $recId -band 0x01 ) -ne 0 )     ) {
        $kG = [ECDSA]::new( $x, $ya )
    } else {
        $kG = [ECDSA]::new( $x, ( $p - $ya ) % $p )
    }
    $Q = ( ( $kG * $s ) + $G * ( (-$z) % $n ) ) * [ECDSA]::ModInv( $r, $n )
    if ( $null -eq $Q -or $Q.Err ) { return $false }
    if ( $header -lt 31 ) {
        $publicKey = "04" + $Q.X.ToHexString64() + $Q.Y.ToHexString64()
    } elseif ( $Q.Y.IsEven ) {
        $publicKey = "02" + $Q.X.ToHexString64()
    } else {
        $publicKey = "03" + $Q.X.ToHexString64()
    }
    if (       $header -ge 27 -and $header -lt 31 ) {
        return $address -ceq ( GetAddressP2PKH       $publicKey -Testnet:$Testnet )
    } elseif ( $header -ge 31 -and $header -lt 35 ) {
        if ( $address -match '^[1mn]' ) {
            return $address -ceq ( GetAddressP2PKH   $publicKey -Testnet:$Testnet )
        } elseif ( $electrum ) {
            if ( $address -match '^[23]' )      { return $address -ceq ( GetAddressP2SH-P2WPKH $publicKey -Testnet:$Testnet ) }
            if ( $address -match '^(bc|tb)1q' ) { return $address -ceq ( GetAddressP2WPKH      $publicKey -Testnet:$Testnet ) }
        }
        return $false
    } elseif ( $header -ge 35 -and $header -lt 39 ) {
        return $address -ceq ( GetAddressP2SH-P2WPKH $publicKey -Testnet:$Testnet )
    } elseif ( $header -ge 39 -and $header -lt 43 ) {
        return $address -ceq ( GetAddressP2WPKH      $publicKey -Testnet:$Testnet )
    } elseif ( $header -ge 43 -and $header -lt 47 ) {
        return $_taprootExtension -and $address -ceq ( GetAddressP2TR $publicKey -Testnet:$Testnet )
    } else {
        throw "invalid header"
    }
}

function VerifyMessageP2TR {
    param( [string]$sig,
           [string]$address,
           [string]$message
    )
    VerifyMessage $sig $address $message -_taprootExtension
}
