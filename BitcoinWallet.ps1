#
# classes and functions for bitcoin wallet managements
#
# Copyright (c) 2022-2024 earthdiver1
#
# This work is licensed under the Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0).
#
using namespace System.Collections.Generic
using namespace System.Security

if ( $PSVersionTable.PSVersion.Major -ge 7 ) {
    If ($IsWindows) {
        If (Test-Path "$($env:LocalAppData)\PackageManagement\NuGet\Packages\RIPEMD160.1.0.0\lib\netcoreapp2.0\RIPEMD160.dll") { 
            Add-Type -A "$($env:LocalAppData)\PackageManagement\NuGet\Packages\RIPEMD160.1.0.0\lib\netcoreapp2.0\RIPEMD160.dll"
	} elseif (Test-Path "$($env:ProgramFiles)\PackageManagement\NuGet\Packages\RIPEMD160.1.0.0\lib\netcoreapp2.0\RIPEMD160.dll") {
            Add-Type -A "$($env:ProgramFiles)\PackageManagement\NuGet\Packages\RIPEMD160.1.0.0\lib\netcoreapp2.0\RIPEMD160.dll"    
        }
    } else {
    	If (Test-Path "$env:HOME/.local/share/PackageManagement/NuGet/Packages/RIPEMD160.1.0.0/lib/netcoreapp2.0/RIPEMD160.dll") {
    	    Add-Type -A "$env:HOME/.local/share/PackageManagement/NuGet/Packages/RIPEMD160.1.0.0/lib/netcoreapp2.0/RIPEMD160.dll"
	} elseif (Test-Path "/usr/local/share/PackageManagement/NuGet/Packages/RIPEMD160.1.0.0/lib/netcoreapp2.0/RIPEMD160.dll") {
	    Add-Type -A "/usr/local/share/PackageManagement/NuGet/Packages/RIPEMD160.1.0.0/lib/netcoreapp2.0/RIPEMD160.dll"
	}
    }
    $loaded = [AppDomain]::CurrentDomain.GetAssemblies().GetName() | ? { $_.Name -eq "RIPEMD160" }
    if ( -not $loaded ) {
	    # Load from a GZip-compressed, Base64-encoded DLL image string (for a Windows Sandbox environment with networking disabled)
        $dll = "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"
        $in=[IO.MemoryStream]::new([Convert]::FromBase64String($dll)); $out=[IO.MemoryStream]::new()
        ([IO.Compression.GZipStream]::new($in,[IO.Compression.CompressionMode]::Decompress)).CopyTo($out)
        [Reflection.Assembly]::Load($out.ToArray()) | Out-Null
    }
}

Update-TypeData -TypeName "bigint" -MemberType "ScriptMethod" -MemberName "ToHexString64" -Force -Value {
    return $this.ToString( "x64" ) -replace '^0(?=[0-9a-f]{64}$)'
}

function i2b {
    # byte array to binary string
    param( [Parameter(ValueFromPipeline=$True)][byte[]]$i )
    begin {
        $buffer = [List[byte]]::new()
    }
    process {
        if ( $i.Count ) { $buffer.AddRange( $i ) }
    }
    end {
        if ( $buffer.Count -eq 0 ) { return }
        return ( $buffer.ToArray() | & { process { [Convert]::ToString( $_, 2 ).PadLeft( 8, "0" ) } } ) -join ""
    }
}

function i2h {
    # byte array to hex string
    param( [Parameter(ValueFromPipeline=$True)][byte[]]$i,
           [Alias("f" )][ValidateRange(1,[Int]::MaxValue)][int]$First    = 0,
           [Alias("l" )][ValidateRange(1,[Int]::MaxValue)][int]$Last     = 0,
           [Alias("p" )][ValidateRange(1,[Int]::MaxValue)][int]$PadLeft  = 0,
           [Alias("sk")][ValidateRange(1,[Int]::MaxValue)][int]$Skip     = 0,
           [Alias("sl")][ValidateRange(1,[Int]::MaxValue)][int]$SkipLast = 0,
           [Alias("r" )][Switch]$Reverse
    )
    begin {
        $buffer = [List[byte]]::new()
    }
    process {
        if ( $i.Count ) { $buffer.AddRange( $i ) }
    }
    end {
        if ( $buffer.Count -eq 0 ) { return }
        if ( $Skip -gt 0 ) {
           if ( $Skip -ge $buffer.Count ) { return }
           $buffer.RemoveRange( 0, $Skip )
        }
        if ( $SkipLast -gt 0 ) {
           if ( $SkipLast -ge $buffer.Count ) { return }
           $buffer.RemoveRange( $buffer.Count - $SkipLast, $SkipLast )
        }
        $n = $First + $Last
        if ( $n -gt 0 -and  $n -lt $buffer.Count ) {
            $buffer.RemoveRange($First, $buffer.Count - $n )
        }
        if ( $Reverse ) { $buffer.Reverse() }
#       return ( ( $buffer.ToArray() | & { process { $_.ToString( "x2" ) } } ) -join "" ).PadLeft( $PadLeft, "0" )
        if ( $PSVersionTable.PSVersion.Major -ge 7 ) {
            $hex_string = [Convert]::ToHexString( $buffer.ToArray() )
        } else {
            $hex_string = [Bitconverter]::ToString( $buffer.ToArray() ).Replace( "-", "" )
        }
        return $hex_string.ToLower().PadLeft( $PadLeft, "0" )
    }
}

function b2i {
    # binary string to byte array
    param( [Parameter(ValueFromPipeline=$True)][string]$b )
    if ( $b -eq "" ) { return }
    $n = $b.Length % 8
    if ( $n ) { $b = "0" * ( 8 - $n ) + $b }
    return $b -split '(.{8})' -ne "" | & { process { [Convert]::ToByte( $_, 2 ) } }
}

function h2i {
    # hex string to byte array
    param( [Parameter(ValueFromPipeline=$True)][string]$h )
    if ( $h -eq "" ) { return }
    if ( $h.Length % 2 -ne 0 ) { $h = "0" + $h }
#   return [byte[]] -split ( $h -replace '..', '0x$& ' )
    if ( $PSVersionTable.PSVersion.Major -ge 7 ) {
        return [Convert]::FromHexString( $h )
    } else {
        return [Runtime.Remoting.Metadata.W3cXsd2001.SoapHexBinary]::Parse( $h ).Value
    }
}

function GetMnemonic {
    param( [Parameter(ValueFromPipeline=$True)][byte[]]$i,
           [Alias("j" )][Switch]$Japanese
    )
    begin {
        if ( $Japanese ) {
            $wordlist = Get-Content "wordlist_jp.txt"
        } else {
            $wordlist = Get-Content "wordlist.txt"
        }
        $buffer = [List[byte]]::new()
    }
    process {
        if ($i.Count) { $buffer.AddRange( $i ) }
    }
    end {
        $entropy  = $buffer.ToArray()
        if ( $entropy.Length -notin @(16,20,24,28,32) ) {
            throw "invalid entropy length"
        }
        $binary   = i2b $entropy
        $SHA256   = New-Object Cryptography.SHA256CryptoServiceProvider
        $checksum = ( i2b $SHA256.ComputeHash( $entropy ) ).Substring( 0, $entropy.Count / 4 )
        $full     = $binary + $checksum
        $mnemonic = ( $full -split '(.{11})' -ne "" | % { [Convert]::ToInt32( $_, 2 ) } | % { $wordlist[$_] } ) -join " "
        return $mnemonic
    }
}

function ValidateMnemonic {
    param( [Parameter(ValueFromPipeline=$True)][string]$mnemonic,
           [Alias("j" )][Switch]$Japanese
    )
    if ( $Japanese ) {
        $wordlist = Get-Content "wordlist_jp.txt"
    } else {
        $wordlist = Get-Content "wordlist.txt"
    }
    $words    = $mnemonic -split '\s+'
    if ( $words.Count -notin @(12, 15, 18, 21, 24) ) { return $false }
    $full     = ( $words | % { [Convert]::ToString( $wordlist.IndexOf( $_ ),2).PadLeft( 11, "0" ) } ) -join ""
    $len      = $full.Length / 33
    $checksum = $full.Substring( $full.Length - $len )
    $entropy  = $full.Substring( 0, $full.Length - $len ) | b2i
    $SHA256   = New-Object Cryptography.SHA256CryptoServiceProvider
    $expected = ( i2b $SHA256.ComputeHash( $entropy ) ).Substring( 0, $entropy.Count / 4 )
    return $checksum -eq $expected
}

Add-Type @'
public class BAXOR {
    public static void Xor( byte[] a, byte[] b ) {
        for(int i = 0; i < a.Length; i++) {
            a[i] = (byte)( a[i] ^ b[i] );
        }
    }
}
'@

function PBKDF2 ([string]$password, [string]$salt, [int]$iterations, [int]$keyLength, [PSObject]$digest) {
    if ( $PSVersionTable.PSVersion.Major -ge 7 ) {
        $result = [Security.Cryptography.Rfc2898DeriveBytes]::Pbkdf2(
            $password.Normalize( "FormKD" ),
            [Text.Encoding]::UTF8.GetBytes( $salt.Normalize( "FormKD" ) ),
            $iterations,
            $digest.HashName,
            $KeyLength
        )
        return ( i2h $result )
    }
    $password = $password.Trim() -replace '\s+',' '  # remove extra spaces
    $digest.key = [Text.Encoding]::UTF8.GetBytes( $password.Normalize( "FormKD" ) )
    $dkLen = $keyLength * 8
    $hLen  = $digest.HashSize
    $bSize = $hLen / 8
    $F0    = [byte[]]::new( $bSize )
    $nb    = [int][Math]::Ceiling( $dkLen / $hLen )
    $T     = [byte[]]@(
        for ( $ib=1; $ib -le $nb; $ib++ ) {
            $U = [Text.Encoding]::UTF8.GetBytes( $salt.Normalize( "FormKD" ) ) + ( h2i $ib.ToString( "x8" ) )
            $F = $F0
            for ( $c = 0 ; $c -lt $iterations; $c++ ) {
                $U = $digest.ComputeHash( $U )
                [BAXOR]::Xor( $F, $U )
            }
            $F
        }
    )
    return ( i2h $T[0..($keyLength-1)] )
}

class ECDSAJ {
# ECDSA in Jacobian coodinates

    [bigint]$X
    [bigint]$Y
    [bigint]$Z

    hidden static [bigint]$p  = [bigint]::Parse( "0fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", "AllowHexSpecifier" )

    ECDSAJ( [bigint]$xj, [bigint]$yj, [bigint]$zj ) {
        $this.X = $xj
        $this.Y = $yj
        $this.Z = $zj
    }

    [ECDSAJ] Add( [bigint]$xa, [bigint]$ya ) {
        $ZZ  = ( $this.Z * $this.Z )                        % [ECDSAJ]::p
        $A   = ( $xa * $ZZ - $this.X )                      % [ECDSAJ]::p
        $B   = ( $ya * ( $ZZ * $this.Z ) - $this.Y )        % [ECDSAJ]::p
        $AA  = ( $A * $A )                                  % [ECDSAJ]::p
        $AAA = ( $A * $AA )                                 % [ECDSAJ]::p
        $XAA = ( $this.X * $AA )                            % [ECDSAJ]::p
        $xj  = ( $B * $B - ( $AAA + 2 * $XAA ) )            % [ECDSAJ]::p
        $yj  = ( $B * ( $XAA - $xj ) - $this.Y * $AAA )     % [ECDSAJ]::p
        $zj  = ( $this.Z * $A )                             % [ECDSAJ]::p
        return [ECDSAJ]::new( $xj, $yj, $zj )
    }

    [ECDSAJ] Double() {
        $YY  = ( $this.Y * $this.Y )                        % [ECDSAJ]::p
        $A   = ( 4 * $this.X * $YY )                        % [ECDSAJ]::p
        $B   = ( 3 * $this.X * $this.X )                    % [ECDSAJ]::p
        $xj  = ( - 2 * $A + $B * $B )                       % [ECDSAJ]::p
        $yj  = ( $B * ( $A - $xj ) - 8 * $YY * $YY )        % [ECDSAJ]::p
        $zj  = ( 2 * $this.Y * $this.Z )                    % [ECDSAJ]::p
        return [ECDSAJ]::new( $xj, $yj, $zj )
    }
    
}

class ECDSA {

    [bigint]$X
    [bigint]$Y
      [bool]$Err
       
    static $p     = [bigint]::Parse( "0fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", "AllowHexSpecifier" )
    static $Order = [bigint]::Parse( "0fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", "AllowHexSpecifier" )

    ECDSA() {
        $this.X   = [bigint]::Parse( "079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "AllowHexSpecifier" )
        $this.Y   = [bigint]::Parse( "0483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", "AllowHexSpecifier" )
        $this.Err = $false
    }
    
    ECDSA( [bigint]$xa, [bigint]$ya ) {
        $yy = ( [bigint]::ModPow( $xa, 3, [ECDSA]::p ) + 7 ) % [ECDSA]::p
        if ( $yy -ne ( $ya * $ya ) % [ECDSA]::p ) {
            $this.Err = $true
            return
        }
        $this.X   = $xa
        $this.Y   = $ya
        $this.Err = $false
    }

    ECDSA( [bigint]$xa ) { # lift_x()
        $yy = ( [bigint]::ModPow( $xa, 3, [ECDSA]::p ) + 7 ) % [ECDSA]::p
        $ya = [bigint]::ModPow( $yy, ([ECDSA]::p + 1)/4, [ECDSA]::p )
        if ( $yy -ne ( $ya * $ya ) % [ECDSA]::p ) {
            $this.Err = $true
            return
        }
        if ( -not $ya.IsEven ) { $ya = ( [ECDSA]::p - $ya ) % [ECDSA]::p }
        $this.X   = $xa
        $this.Y   = $ya
        $this.Err = $false
    }

    ECDSA( [ECDSAJ]$j ) {
        if ( $j.Z -eq [bigint]::Zero ) { 
            $this.Err = $true
            return
        }
        $INVZ  = [ECDSA]::ModInv( $j.Z )
        $INVZZ = ( $INVZ * $INVZ ) % [ECDSA]::p
        $this.X = ( $j.X * $INVZZ         ) % [ECDSA]::p
        $this.Y = ( $j.Y * $INVZZ * $INVZ ) % [ECDSA]::p
        if ( $this.X.Sign -eq -1 ) { $this.X += [ECDSA]::p }
        if ( $this.Y.Sign -eq -1 ) { $this.Y += [ECDSA]::p }
        $this.Err = $false
    }

    hidden [ECDSA] Add( [ECDSA]$point ) {
        $slope = (( $point.Y - $this.Y ) * [ECDSA]::ModInv( $point.X - $this.X ) )   % [ECDSA]::p
        $xout  = ( $slope * $slope - $this.X - $point.X )                            % [ECDSA]::p
        $yout  = ( $slope * ($this.X - $xout) - $this.Y )                            % [ECDSA]::p
        return [ECDSA]::new( $xout, $yout )
    }

    hidden [ECDSA] Double() {
        $slope = ( 3 * $this.X * $this.X * [ECDSA]::ModInv( 2 * $this.Y ) )          % [ECDSA]::p
        $xout  = ( $slope * $slope - 2 * $this.X )                                   % [ECDSA]::p
        $yout  = ( $slope * ( $this.X - $xout ) - $this.Y )                          % [ECDSA]::p
        return [ECDSA]::new( $xout, $yout )
    }

    static [ECDSA] op_Addition( [ECDSA]$left, [ECDSA]$right ) {
        if ( $left  -eq $null ) { return $right }
        if ( $right -eq $null ) { return $left  }
        if ( $left.X -eq $right.X ) {
            if ( $left.Y -ne $right.Y ) { return $null }
            $result = $left.Double()
        } else {
            $result = $left.Add( $right )
        }
        if ( $result.X.Sign -eq -1 ) { $result.X += [ECDSA]::p }
        if ( $result.Y.Sign -eq -1 ) { $result.Y += [ECDSA]::p }
        return $result;
    }

    static [ECDSA] op_Multiply( [ECDSA]$left, [bigint]$right ) {
        if ( $right -eq [bigint]::Zero ) { return $null }
        if ( $right -eq [bigint]::One  ) { return $left }
        $right %= [ECDSA]::Order
        if ( $right.Sign -eq -1 ) { $right += [ECDSA]::Order }
        $buffer = [List[char]]::new()
        while ( $right -ne [bigint]::One ) {
            if ( $right.IsEven ) {
                $buffer.Add( "0" )
            } else {
                $n = [bigint]2 - $right % 4
                switch ( [int]$n ) {
                    -1 { $buffer.Add( "n" ) }
                     1 { $buffer.Add( "p" ) }
                }
                $right -= $n
            }
            $right /= 2
        }
        $buffer.Reverse()
        $naf = $buffer.ToArray() -join ""
        $resultJ = [ECDSAJ]::new( $left.X,  $left.Y, [bigint]::One )
        foreach ( $c in $naf.ToCharArray() ) {
            $resultJ = $resultJ.Double()
            switch ( $c ) {
                "p" { $resultJ = $resultJ.Add( $left.X,  $left.Y ) }
                "n" { $resultJ = $resultJ.Add( $left.X, -$left.Y ) }
            }
        }
        $result = [ECDSA]::new( $resultJ )
        if ( $result.Err ) { return $null }
        return $result
    }
    
    static [ECDSA] op_Implicit( [bigint]$i ) { # workaround for enabling the operator overloading ( [ECDSA] * [bigint] )
        return $i
    }
    
    static [bigint] ModInv( [bigint]$a ) {
        return [ECDSA]::ModInv( $a, [ECDSA]::p )
    }
    static [bigint] ModInv( [bigint]$a, [bigint]$m ) {
        # the extended Euclidean algorithm
        $a %= $m
        if ( $a.Sign -eq -1 ) { $a += $m }
        $inv, $prev = [bigint]::One, [bigint]::Zero
        $m_ = $m
        while ( -not $a.IsOne ) {
            $a_ = $a
            $q  = [bigint]::DivRem( $m_, $a_, [ref] $a )
            $inv, $prev, $m_ = ( $prev - $q * $inv ), $inv, $a_
        }
        $inv %= $m
        if ( $inv.Sign -eq -1 ) { $inv += $m }
        return $inv
    }
    
}

function GetPublicKey {
    param( [Parameter(ValueFromPipeline=$True)][string]$privateKey,
           [Alias("uc")][Switch]$UnCompressed
    )
    if ( $privateKey.Length -ne 64 ) { throw "invalid length" }
    $secretKey = [bigint]::Parse( "0" + $privateKey, "AllowHexSpecifier" )
    if ( $secretKey.IsZero -or $secretKey -ge [ECDSA]::Order ) {
        throw "invalid private key"
    }
    $G       = [ECDSA]::new()
    $pubkey  = $G * $secretKey
    if ( $pubkey -eq $null ) { throw "arithmetic error" }
    $pubkeyX = $pubkey.X.ToHexString64()
    $pubkeyY = $pubkey.Y.ToHexString64()
    if ( -not $UnCompressed ) {
        if ( $pubkey.Y.IsEven ) {
            return "02" + $pubkeyX
        } else {
            return "03" + $pubkeyX
        }
    } else {
        return "04" + $pubkeyX + $pubkeyY
    }
}

function GetPublicKeyFromWIF {
    param( [Parameter(ValueFromPipeline=$True)][string]$wif )
    $buffer = Base58Check_Decode $wif
    if ( $buffer ) {
        if ( $buffer.Length -ne 66 -and $buffer.Length -ne 68 ) { throw "invalid length" }
        if ( $buffer.Substring( 0, 2 ) -notin @( "80", "ef" ) ) { throw "invalid prefix" }
        $suffix = $buffer.Substring( $buffer.Length - 2 )
        if ( $buffer.Length -eq 68 -and $suffix -ne "01" )      { throw "invalid suffix" }
        $privateKey = $buffer.Substring( 2, 64 )
        if ( $buffer.Length -eq 68 ) {
            $publicKey = GetPublicKey      $privateKey           # compressed
        } else {
            $publicKey = GetPublicKey -uc  $privateKey           # uncompressed
        }
        return $publicKey
    }
}

function DecompressPublicKey {
    param( [Parameter(ValueFromPipeline=$True)][string]$publicKey )
    if ( $publicKey.Length -ne 33 * 2 ) { throw "invalid length" }
    $prefix     = $publicKey.Substring( 0, 2 )
    if ( $prefix -cnotmatch '^0[23]$' ) { throw "invalid prefix" }
    $publicKeyX = $publicKey.Substring( 2 )
    $x  = [bigint]::Parse( "0" + $publicKeyX, "AllowHexSpecifier" )
    $p = [ECDSA]::p
    if ( $x -ge $p ) { throw "invalid public key" }
    $y  = [ECDSA]::new( $x ).Y                                        # $y is even
    if ( $prefix -eq "03" ) { $y = ($p - $y) % $p }
    $publicKeyY = $y.ToHexString64()
    return "04" + $publicKeyX + $publicKeyY
}

function Hash160 {
    param( [Parameter(ValueFromPipeline=$True)][string]$hex_string )
    if ( $hex_string -eq "" ) { throw "input is empty" }
    if ( $hex_string.Length % 2 -ne 0 ) { $hex_string = "0" + $hex_string }
    $SHA256 = New-Object Cryptography.SHA256CryptoServiceProvider
    $RIPEMD160 = New-Object Cryptography.RIPEMD160Managed
    $hash = i2h $RIPEMD160.ComputeHash( $SHA256.ComputeHash( ( h2i $hex_string ) ) )
    return $hash
}

function Hash256 {
    param( [Parameter(ValueFromPipeline=$True)][string]$hex_string )
    if ( $hex_string -eq "" ) { throw "input is empty" }
    if ( $hex_string.Length % 2 -ne 0 ) { $hex_string = "0" + $hex_string }
    $SHA256 = New-Object Cryptography.SHA256CryptoServiceProvider
    $hash = i2h $SHA256.ComputeHash( $SHA256.ComputeHash( ( h2i $hex_string ) ) )
    return $hash
}

function Base58Check_Encode {
    param( [Parameter(ValueFromPipeline=$True)][string]$hex_string )
    $charset  = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    $checksum = ( Hash256 $hex_string ).Substring( 0, 8 )
    $i        = [bigint]::parse( "0" + $hex_string + $checksum, "AllowHexSpecifier" )
    $remainder= [bigint]::Zero
    $buffer   = @(
        while ( $i -gt 0 ) {
            $i = [bigint]::DivRem( $i, 58, [ref] $remainder )
            $charset[$remainder]
        }
    )
    [Array]::Reverse( $buffer )
    $leadingones = $hex_string -replace '^((?:00)*).*$','$1' -replace '00','1'
    $base58check = $leadingones + ( $buffer -join "" )
    return $base58check
}

function Base58Check_Decode {
    param( [Parameter(ValueFromPipeline=$True)][string]$base58check )
    $charset = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    $i =[bigint]0
    foreach ( $c in $base58check.ToCharArray() ) {
        $digit = $charset.IndexOf( $c )
        if ( $digit -lt 0 ) { throw "invalid character ($c)" }
        $i = $i * 58 + $digit
    }
    $buffer     = $i.ToByteArray()
    $checksum   = $buffer   | i2h -first 4 -r
    $hex_string = ( $buffer | i2h -skip  4 -r ) -replace '^00'
    $leading0s  = $base58check -replace '^(1*).*$','$1' -replace '1','00'
    $hex_string = $leading0s + $hex_string
    $expected   = ( Hash256 $hex_string ).Substring( 0, 8 )
    if ( $checksum -eq $expected ) { return $hex_string }
}

function Bech32_Encode {
    param( [Parameter(ValueFromPipeline=$True)][string]$hex_string, [string]$hrp, [bool]$m, [int]$v )
    if ( $hex_string.Length -ne 20*2 -and $hex_string.Length -ne 32*2 -and $hex_string.Length -ne 66*2 ) {
        throw "invalid length"
    }
    $charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    $separator = "1"
    $data = ( $hex_string | h2i | i2b ) -split '(.{5})' -ne "" | % { b2i $_.PadRight( 5, "0" ) }
    $data = @( $v ) + $data  # prepend the witness version
    $str  = ( $data | % { $charset[$_] } ) -join ""
    $hrp_expanded = ( ( $hrp.ToCharArray() | % { [byte][char]$_ -shr 5 } ) + @( 0 ) +
                      ( $hrp.ToCharArray() | % { [byte][char]$_ -band 0x1f } )       )
    $values = $hrp_expanded + $data
    $gen   = @(0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
    $chk = 1
    ( $values + @(0,0,0,0,0,0) ) | % {
        $b = $chk -shr 25
        $chk = ( ( $chk -band 0x01ffffff ) -shl 5 ) -bxor $_
        0..4 | % { $chk = $chk -bxor ( $gen[$_] * (( $b -shr $_ ) -band 0x00000001) ) }
    }
    if ( $m ) {
        $chk = $chk -bxor 0x2bc830a3
    } else {
        $chk = $chk -bxor 0x00000001
    }
    $chk = ( 0..5 | % { ( $chk -shr 5 * (5 - $_) ) -band 0x0000001f } | % { $charset[$_] } ) -join ""
    return $hrp + $separator + $str + $chk
}

function Bech32_Decode {
    param( [Parameter(ValueFromPipeline=$True)][string]$bech32, [bool]$m )
    $charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    if ( $bech32 -cnotmatch '^((bc|tb)1(q|p)|t?sp1q)' ) { throw "invalid Bech32 address" }
    if ( $bech32 -cmatch '^tsp1q' ) {
        $hrp = $bech32.Substring( 0, 3 )
        $str = $bech32.Substring( 4, $bech32.Length - 10 )
    } else {
        $hrp = $bech32.Substring( 0, 2 )
        $str = $bech32.Substring( 3, $bech32.Length - 9 )
    }
    $checksum = $bech32.Substring( $bech32.Length - 6 )
    $b_string = [Text.StringBuilder]::new()
    $data     = @(
        foreach ( $c in $str.ToCharArray() ) {
            $digit = $charset.IndexOf( $c )
            if ( $digit -lt 0 ) { throw "invalid character ($c)" }
            $digit
            $null = $b_string.Append( [Convert]::ToString( $digit, 2 ).PadLeft( 5, "0" ) )
        }
    )
    $b_string = $b_string.ToString()
    $h_string = $b_string.Substring( 5, [Math]::Floor( ($b_string.Length - 5)/ 8 ) * 8 ) | b2i | i2h
    if ( $h_string.Length -ne 20*2 -and $h_string.Length -ne 32*2 -and $h_string.Length -ne 66*2 ) {
        throw "invalid length"
    }
    $hrp_expanded =           $hrp.ToCharArray() | % { [byte][char]$_ -shr 5 }
    $hrp_expanded += @( 0 ) + $hrp.ToCharArray() | % { [byte][char]$_ -band 0x1f }
    $values = $hrp_expanded + $data
    $gen   = @(0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
    $chk = 1
    ( $values + @(0,0,0,0,0,0) ) | % {
        $b = $chk -shr 25
        $chk = ( ( $chk -band 0x01ffffff ) -shl 5 ) -bxor $_
        0..4 | % { $chk = $chk -bxor ( $gen[$_] * (( $b -shr $_ ) -band 0x00000001 ) ) }
    }
    if ( $m ) {
        $chk = $chk -bxor 0x2bc830a3
    } else {
        $chk = $chk -bxor 0x00000001
    }
    $expected = ( 0..5 | % { ( $chk -shr 5 * (5 - $_) ) -band 0x0000001f } | % { $charset[$_] } ) -join ""
    if ( $checksum -ne $expected ) { throw "checksum mismatch" }
    return $h_string
}

function GetWIF {
    param( [Parameter(ValueFromPipeline=$True)][string]$privateKey,
           [Alias("uc")][switch]$UnCompressed,
           [Alias("t") ][switch]$Testnet
         )
    $prefix = if ( -not $Testnet ) { "80" } else { "ef" }
    $suffix = if ( $UnCompressed ) { ""   } else { "01" }
    return ( Base58Check_Encode ( $prefix + $privateKey + $suffix ) )
}

function GetAddressP2PKH {
    param( [Parameter(ValueFromPipeline=$True)][string]$publicKey, [Alias("t")][switch]$Testnet )
    $pubkeyHash = Hash160 $publicKey 
    $prefix = if ( -not $Testnet ) { "00" } else { "6f" }
    return ( Base58Check_Encode ( $prefix + $pubkeyHash ) )
}

function GetAddressP2WPKH {
    param( [Parameter(ValueFromPipeline=$True)][string]$publicKey, [Alias("t")][switch]$Testnet )
    $pubkeyHash = Hash160 $publicKey
    $hrp = if ( -not $Testnet ) { "bc" } else { "tb" }
    return ( Bech32_Encode $pubkeyHash $hrp $false 0 )
}

function GetAddressP2SH {
    param( [Parameter(ValueFromPipeline=$True)][string]$publicKey, [Alias("t")][switch]$Testnet )
    $prefix = if ( -not $Testnet ) { "05" } else { "c4" }
    $redeemScript = "21" + $publicKey + "ac"                          # PUSH(publickey) + OP_CHECKSIG
    $scriptHash = Hash160 $redeemScript
    return ( Base58Check_Encode ( $prefix + $scriptHash ) )
}

function GetAddressP2SH-P2WPKH {
    param( [Parameter(ValueFromPipeline=$True)][string]$publicKey, [Alias("t")][switch]$Testnet )
    $prefix = if ( -not $Testnet ) { "05" } else { "c4" }
    $redeemScript = "0014" + ( Hash160 $publicKey )                   # 0014: witnessversion(0) + push20bytes
    $scriptHash = Hash160 $redeemScript
    return ( Base58Check_Encode ( $prefix + $scriptHash ) )
}

function GetAddressP2SH-P2WSH {
    param( [Parameter(ValueFromPipeline=$True)][string]$publicKey, [Alias("t")][switch]$Testnet )
    $prefix = if ( -not $Testnet ) { "05" } else { "c4" }
    $SHA256 = New-Object Cryptography.SHA256CryptoServiceProvider
    $witnessScript = "21" + $publicKey + "ac"                         # PUSH(publickey) + OP_CHECKSIG
    $redeemScript  = "0020" + ( i2h $SHA256.ComputeHash( ( h2i $witnessScript ) ) )  # 0020: witnessversion(0) + push32bytes
    $scriptHash    = Hash160 $redeemScript
    return ( Base58Check_Encode ( $prefix + $scriptHash ) )
}

function GetAddressP2WSH {
    param( [Parameter(ValueFromPipeline=$True)][string]$publicKey, [Alias("t")][switch]$Testnet )
    $SHA256 = New-Object Cryptography.SHA256CryptoServiceProvider
    $witnessScript = "21" + $publicKey + "ac"                         # PUSH(publickey) + OP_CHECKSIG
    $scriptHash    = i2h $SHA256.ComputeHash( ( h2i $witnessScript ) )
    $hrp = if ( -not $Testnet ) { "bc" } else { "tb" }
    return ( Bech32_Encode $scriptHash $hrp $false 0 )
}

function GetTweak {
# Tweak for an unspendable script path (BIP-0086)
    param( [Parameter(ValueFromPipeline=$True)][string]$publicKey )
    $SHA256 = New-Object Cryptography.SHA256CryptoServiceProvider
    $publicKeyX = $publicKey.Substring( 2 )
    $tag = [Text.Encoding]::UTF8.GetBytes( "TapTweak" )
    $hash = $SHA256.ComputeHash( $SHA256.ComputeHash( $tag ) * 2 + ( h2i $publicKeyX ) )
    $tweak = [bigint]::new( $hash[31..0] + @(0x00) )
    if ( $tweak.IsZero -or $tweak -ge [ECDSA]::Order ) {
        throw "Tweak is zero or greater than ( the order of the curve - 1 )."
    }
    return $tweak
}

function GetTweakedWIF {
# Tweaked secret key ( in WIF ) for an unspendable script path (BIP-0086)
    param( [Parameter(ValueFromPipeline=$True)][string]$wif )
    $n = [ECDSA]::Order
    $G = [ECDSA]::new()
    $privateKey = ( Base58Check_Decode $wif ).Substring( 2 )
    if ( $privateKey.Length -ne 66 -or $privateKey.Substring( 64, 2 ) -ne "01" ) {
        throw "invalid WIF"
    }
    $privateKey = $privateKey.Substring( 0, 64 )
    $d          = [bigint]::Parse( "0" + $privateKey, "AllowHexSpecifier" )
    if ( $d.IsZero -or $d -ge $n ) { throw "invalid private key" }
    $P          = $G * $d
    if ( $P -eq $null ) { throw "arithmetic error" }
    if ( -not $P.Y.IsEven ) { $d = $n - $d }
    $publicKey  = GetPublicKey $privateKey
    $t          = GetTweak $publicKey
    $td         = ( $d + $t ) % $n
    $td_hex     = $td.ToHexString64()
    $prefix     = if ( $wif -cmatch '^[KL]' ) { "80" } else { "ef" }
    return Base58Check_Encode ( $prefix + $td_hex + "01" )
}

function GetAddressP2TR {
# Taproot address for a single key (BIP-0086)
    param( [Parameter(ValueFromPipeline=$True)][string]$publicKey, [Alias("t")][switch]$Testnet )
    $internalKey = $publicKey.Substring( 2 )
    $x = [bigint]::Parse( "0" + $internalKey, "AllowHexSpecifier" )
    $P = [ECDSA]::new( $x )
    $G = [ECDSA]::new()
    $tweak = GetTweak $publicKey
    $Q = $P + $G * $tweak
    if ( $Q -eq $null ) { throw "The resulting address is invalid." }
    $outputKey  = $Q.X.ToHexString64()
    $hrp = if ( -not $Testnet ) { "bc" } else { "tb" }
    return ( Bech32_Encode $outputKey $hrp $true 1 )
}

function GetURI { # BIP-0021
# Convenient when used in combination with the following QRcode generator.
# (qrcode.ps1: https://gist.github.com/mizar/a2d535c1b91a676cc20fd979043857be )
    param ( [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
            [string]$address,
            [double]$amount,
            [string]$label,
            [string]$message
          )
    $uri = "bitcoin:" + $address
    if ( $amount  ) { $uri += "?amount="  + $amount.ToString() }
    if ( $label   ) { $uri += "?label="   + $label             }
    if ( $message ) { $uri += "?message=" + $message           }
    $uri = [uri]::EscapeUriString( $uri ) -replace '(?<=\?.*)\?','&'
    return $uri
}

class HDWallet {
    [string]   $Seed
    [int]      $Depth
    [UInt32]   $Index
    [string]   $PrivateKey
    [string]   $ChainCode
    [string]   $PublicKey
    [string]   $PublicKeyUC
    [string]   $Path
    [bool]     $Hardened
    [bool]     $Testnet
    [HDWallet] $Parent
    [string]   $FingerPrint

    hidden [Dictionary[String, HDWallet]]$Dict

    HDWallet () {
        $this.Seed        = $null
        $this.Depth       = $null
        $this.Index       = $null
        $this.PrivateKey  = $null
        $this.ChainCode   = $null
        $this.PublicKeyUC = $null
        $this.PublicKey   = $null
        $this.Path        = $null
        $this.Hardened    = $null
        $this.Testnet     = $null
        $this.Parent      = $null
        $this.FingerPrint = $null
        $this.Dict        = $null
    }

    HDWallet ( [string]$seed ) {
        $this.Init( $seed, $false )
    }

    HDWallet ( [string]$seed, [bool]$testnet ) {
        $this.Init( $seed, $testnet )
    }

    hidden [void] Init ( [string]$seed, [bool]$testnet ) {
        Add-Type -AssemblyName System.Security

        $HMACSHA512      = New-Object Cryptography.HMACSHA512
        $HMACSHA512.Key  = [Text.Encoding]::UTF8.GetBytes( "Bitcoin seed" )
        $bytes           = h2i $seed
        $extendedKey     = $HMACSHA512.ComputeHash( $bytes )

        $il = [bigint]::new( $extendedKey[31..0]  + @(0x00) )
        if ( $il.IsZero -or $il -ge [ECDSA]::Order ) {
            throw "Result of digest is zero or greater than the order of the curve. Try a different seed."
        }

        $this.Seed        = $seed
        $this.Depth       = 0
        $this.Index       = 0
        $this.PrivateKey  = i2h $extendedKey[0..31]
        $this.ChainCode   = i2h $extendedKey[32..63]
        $this.PublicKeyUC = GetPublicKey -uc $this.PrivateKey
        $prefix           = if ( $this.PublicKeyUC -cmatch '[02468ace]$' ) { "02" } else { "03" }
        $this.PublicKey   = $prefix + $this.PublicKeyUC.Substring( 2, 64 )
        $this.Path        = "m"
        $this.Hardened    = $false
        $this.Testnet     = $testnet
        $this.Parent      = $null
        $this.FingerPrint = ( Hash160 $this.PublicKey ).SubString( 0, 8 )

        $this.Dict = [Dictionary[String, HDWallet]]::new()
        $this.Dict.Add( $this.Path, $this )
    }

    [HDWallet] Derive ( [int]$index, [bool]$hardened ) {
        $child_path  = $this.Path + "/" + $index.ToString( "d" )
        if ( $hardened ) {  $child_path  += "'" }
        if (       $child_path -cmatch "^m/(?!0')\d+'/0'" ) {
            $child_Testnet = $false                                   # Mainnet Bitcoin
        } elseif ( $child_path -cmatch "^m/(?!0')\d+'/1'" ) {
            $child_Testnet = $true                                    # Testnet Bitcoin
        } else {
            $child_Testnet = $this.Testnet                            # inherit from the parent object
        }
        return $this.Derive( $index, $hardened, $child_Testnet )
    }

    [HDWallet] Derive ( [int]$index, [bool]$hardened, [bool]$testnet ) {
        if ( $index -lt 0 ) {
            Write-Host "Index must be between 0 and 2^31 - 1." -Fore Red
            return $null
        }

        if ( -not $this.PrivateKey -and $hardened ) {
            Write-Host "Not possible to derive a child without the private key." -Fore Red
            return $null
        }

        $child_path  = $this.Path + "/" + $index.ToString( "d" )

        if ( $hardened ) {  $child_path  += "'" }

        if (( $child_path -cmatch "^m/(?!0')\d+'/0'" -and $testnet -eq $true  ) -or `
            ( $child_path -cmatch "^m/(?!0')\d+'/1'" -and $testnet -eq $false )     ) {
            Write-Host "Coin type is inconsistent." -Fore Red
            return $null
        }

        if ( $this.Dict.ContainsKey( $child_path ) ) { return $this.Dict.Item( $child_path ) }

        $child_index     = [UInt32]$index
        if ( $hardened ) { $child_index += [UInt32]"0x80000000" }
        $child_depth     = $this.Depth + 1
        $child_Testnet   = $testnet

        $HMACSHA512      = New-Object Cryptography.HMACSHA512
        $HMACSHA512.Key  = h2i $this.ChainCode

        if ( -not $hardened ) {
            $bytes = h2i $this.PublicKey
        } else {
            $bytes = h2i ( "00" + $this.PrivateKey )
        }
        $bytes += h2i $child_index.ToString( "x8" )

        $extendedKey = $HMACSHA512.ComputeHash( $bytes )

        $il = [bigint]::new( $extendedKey[31..0]  + @(0x00) )

        if ( $il -ge [ECDSA]::Order ) {
            Write-Host "The resulting key is invalid. Try the next index." -Fore Red
            return $null
        }

        if ( $this.PrivateKey ) {

            $kp = [bigint]::Parse( "0" + $this.PrivateKey, "AllowHexSpecifier" )
            $kc = ( $il + $kp ) % [ECDSA]::Order
            if ( $kc.IsZero ) {
                Write-Host "The resulting key is invalid. Try the next index." -Fore Red
                return $null
            }

            $child_privateKey  = $kc.ToHexString64()
            $child_publicKeyUC = GetPublicKey -uc $child_privateKey
            $prefix            = if ( $child_publicKeyUC -cmatch '[02468ace]$' ) { "02" } else { "03" }
            $child_publicKey   = $prefix + $child_publicKeyUC.Substring( 2, 64 )

        } else {

            $G   = [ECDSA]::new()
            $publicKeyX = $this.PublicKeyUC.Substring( 2, 64 )
            $publicKeyY = $this.PublicKeyUC.Substring( 66 )
            $kpX = [bigint]::Parse( "0" + $publicKeyX, "AllowHexSpecifier" )
            $kpY = [bigint]::Parse( "0" + $publicKeyY, "AllowHexSpecifier" )
            $Kp  = [ECDSA]::new( $kpX, $kpY )
            if ( $Kp.Err ) {
                Write-Host "Kp is not on the curve." -Fore Red
                return $null
            }
            $Pc  = $G * $il + $Kp
            if ( $Pc -eq $null ) {
                Write-Host "The resulting key is invalid. Try the next index." -Fore Red
                return $null
            }
            $pubkeyX = $Pc.X.ToHexString64()
            $pubkeyY = $Pc.Y.ToHexString64()

            $child_privateKey  = $null
            $child_publicKeyUC = "04" + $pubkeyX + $pubkeyY
            $prefix            = if ( $Pc.Y.IsEven ) { "02" } else { "03" }
            $child_publicKey   = $prefix + $pubkeyX

        }

        $child_chainCode = i2h $extendedKey[32..63]

        return [HDWallet]::new($child_depth, $child_index, $child_privateKey, $child_chainCode, $child_publicKeyUC, $child_publicKey, $child_path, $child_Testnet, $this)
    }

    hidden HDWallet ([int]$depth, [UInt32]$index, [string]$privateKey, [string]$chainCode, [string]$publicKeyUC, [string]$publicKey, [string]$path, [bool]$testnet, [HDWallet]$parent) {
        $this.Seed        = $parent.Seed
        $this.Depth       = $depth
        $this.Index       = $index
        $this.PrivateKey  = $privateKey
        $this.ChainCode   = $chainCode
        $this.PublicKeyUC = $publicKeyUC
        $this.PublicKey   = $publicKey
        $this.Path        = $path
        $this.Hardened    = $index -ge [UInt32]"0x80000000"
        $this.Testnet     = $testnet
        $this.Parent      = $parent
        $this.FingerPrint = ( Hash160 $publicKey ).SubString( 0, 8 )
        $this.Dict        = $parent.Dict

        $this.Dict.Add( $this.Path, $this )
    }

    [void] Dispose() {
        # dispose the child objects
        $wallets = [HDWallet[]]$this.Dict.Values
        $wallets | ? { $this -eq $_.Parent } | % { $_.Dispose() }

        $null = $this.Dict.Remove( $this.Path )

        $this.Seed        = $null
        $this.Depth       = $null
        $this.Index       = $null
        $this.PrivateKey  = $null
        $this.ChainCode   = $null
        $this.PublicKeyUC = $null
        $this.PublicKey   = $null
        $this.Path        = $null
        $this.Hardened    = $null
        $this.Testnet     = $null
        $this.Parent      = $null
        $this.FingerPrint = $null
        $this.Dict        = $null
        $this             = $null
    }

#
# Prefixes Reference
#  P2PKH, WIF   : https://en.bitcoin.it/wiki/List_of_address_prefixes
#  P2SH-P2WPKH  : https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki#Address_derivation
#  P2WPKH, P2WSH: https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki#Address_derivation
#                 https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
#                 https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
#  P2TR         : https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki
#  Serialization: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Serialization_format
#                 https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki#Extended_Key_Version
#                 https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki#Extended_Key_Version
#                 https://github.com/satoshilabs/slips/blob/master/slip-0132.md
#

    [void] ImportExtendedKey( [string]$extendedKey, [string]$path ) {
        $this.ImportExtendedKey( $extendedKey, $path, $false )
    }

    [void] ImportExtendedKey( [string]$extendedKey, [string]$path, [bool]$testnet ) {

        $serialized = Base58Check_Decode $extendedKey

        if ( -not $serialized ) { Write-Host "Not properly deserialized." -Fore Red ; return }
        $version_e      = $serialized.Substring(  0,  8 )
        $depth_e        = $serialized.Substring(  8,  2 )
        $pFingerprint_e = $serialized.Substring( 10,  8 )
        $index_e        = $serialized.Substring( 18,  8 )
        $chainCode_e    = $serialized.Substring( 26, 64 )
        $extendedKey_e  = $serialized.Substring( 90, 66 )

        $prefixes_prv   = @("024285b5","02575048","0295b005","02aa7a99","04358394","044a4e28","045f18bc","0488ade4","049d7878","04b2430c")
        $prefixes_pub   = @("024289ef","02575483","0295b43f","02aa7ed3","043587cf","044a5262","045f1cf6","0488b21e","049d7cb2","04b24746")

        if ( $version_e -in $prefixes_prv ) {
            $this.PrivateKey  = $extendedkey_e -replace '^00'
            $this.PublicKeyUC = GetPublicKey -uc $this.PrivateKey
            $prefix = if ( $this.PublicKeyUC -cmatch '[02468ace]$' ) { "02" } else { "03" }
            $this.PublicKey = $prefix + $this.PublicKeyUC.Substring( 2, 64 )
        } elseif ( $version_e -in $prefixes_pub ) {
            $this.PrivateKey  = $null
            $this.PublicKeyUC = DecompressPublicKey $extendedKey_e
            $this.PublicKey   = $extendedKey_e
        } else {
            Write-Host "Invalid prefix." -Fore Red
            return
        }

        $this.Seed        = $null
        $this.Depth       = [Convert]::ToInt32( $depth_e, 16 )
        $this.FingerPrint = ( Hash160 $this.PublicKey ).SubString( 0, 8 )
        $this.Index       = [Convert]::ToInt64( $index_e, 16 )
        $this.ChainCode   = $chainCode_e
        $this.Path        = $path
        $this.Hardened    = $this.Index -ge [UInt32]"0x80000000"
        $this.Testnet     = $testnet

        if ( $this.Depth -ne ( $path -replace '[^/]' ).Length ) {
             Write-Host "The depths in the extended key and the path are inconsistent." -Fore Red
             return
        }
        if ( $path -eq "m" ) {
            $idx = 0
        } else {
            $idx = [int]( $path -replace '^.+/(\d+)''?$','$1' )
        }
        if ( $this.Index % [UInt32]"0x80000000" -ne $idx ) {
             Write-Host "The indexes in the extended key and the path are inconsistent." -Fore Red
             return
        }
        if (      $this.Hardened -and $path[-1] -ne "'" -or
             -not $this.Hardened -and $path[-1] -eq "'"     ) {
            Write-Host "The types (normal/hardened) in the extended key and the path are inconsistent." -Fore Red
            return
        }

        $this.Dict = [Dictionary[String, HDWallet]]::new()
        $this.Dict.Add( $this.Path, $this )

        if ( $path -eq "m" ) {
            $this.Parent = $null
        } else {
            $this.Parent             = [HDWallet]::new()
            $this.Parent.FingerPrint = $pFingerprint_e
            $this.Parent.Path        = $this.Path -replace '/[^/]+$'
            $this.Dict.Add( $this.Parent.Path, $this.Parent )
        }

    }

    [string] GetExtendedPrivateKey( [bool]$testnet ) {
        return $this.GetExtendedPrivateKey( $testnet, $false )
    }
    [string] GetExtendedPrivateKey( [bool]$testnet, [bool]$forceXpub ) {
        if ( -not $this.PrivateKey ) {
            Write-Host "PrivateKey is unknown." -Fore Red
            return $null
        }
        $version_e = ""
        if ( -not $testnet ) {
            switch -Regex ( $this.Path ) {
                "^m/48'/0'/0'/1'" { $version_e = "0295b005" } # P2SH-P2WSH multisig (SLIP-0132)
                "^m/48'/0'/0'/2'" { $version_e = "02aa7a99" } # P2WSH multisig (SLIP-0132)
                "^m/49'"          { $version_e = "049d7878" } # P2SH-P2WPKH (BIP-0049)
                "^m/(84|0)'"      { $version_e = "04b2430c" } # P2WPKH (BIP-0084), electrum
                default           { $version_e = "0488ade4" } # BIP-0044
            }
        } else {
            switch -Regex ( $this.Path ) {
                "^m/48'/0'/0'/1'" { $version_e = "024285b5" } # P2SH-P2WSH multisig (SLIP-0132)
                "^m/48'/0'/0'/2'" { $version_e = "02575048" } # P2WSH multisig (SLIP-0132)
                "^m/49'"          { $version_e = "044a4e28" } # P2SH-P2WPKH (BIP-0049)
                "^m/(84|0)'"      { $version_e = "045f18bc" } # P2WPKH (BIP-0084), electrum
                default           { $version_e = "04358394" } # BIP-0044
            }
        }
        if ( $forceXpub ) {
            if ( -not $testnet ) {
                $version_e = "0488ade4"
            } else {
                $version_e = "04358394"
            }
        }
        $depth_e = $this.Depth.ToString( "x2" )
        if ( $this.Parent ) {
            $pFingerprint_e = $this.Parent.FingerPrint
        } else {
            $pFingerprint_e = "00000000"
        }
        $index_e      = $this.Index.ToString( "x8" )
        $chainCode_e  = $this.Chaincode
        $privateKey_e = "00" + $this.PrivateKey
        $serialized   = $version_e + $depth_e + $pFingerprint_e + $index_e + $chainCode_e + $privateKey_e
        return ( Base58Check_Encode $serialized )
    }

    [string] GetExtendedPublicKey( [bool]$testnet ) {
        return $this.GetExtendedPublicKey( $testnet, $false )
    }
    [string] GetExtendedPublicKey( [bool]$testnet, [bool]$forceXpub ) {
        $version_e = ""
        if ( -not $testnet ) {
            switch -Regex ( $this.Path ) {
                "^m/48'/0'/0'/1'" { $version_e = "0295b43f" } # P2SH-P2WSH multisig (SLIP-0132)
                "^m/48'/0'/0'/2'" { $version_e = "02aa7ed3" } # P2WSH multisig (SLIP-0132)
                '^m/49'''         { $version_e = "049d7cb2" } # P2SH-P2WPKH (BIP-0049)
                '^m/(84|0)'''     { $version_e = "04b24746" } # P2WPKH (BIP-0084), electrum
                default           { $version_e = "0488b21e" } # BIP-0044
            }
        } else {
            switch -Regex ( $this.Path ) {
                "^m/48'/0'/0'/1'" { $version_e = "024289ef" } # P2SH-P2WSH multisig (SLIP-0132)
                "^m/48'/0'/0'/2'" { $version_e = "02575483" } # P2WSH multisig (SLIP-0132)
                '^m/49'''         { $version_e = "044a5262" } # P2SH-P2WPKH (BIP-0049)
                '^m/(84|0)'''     { $version_e = "045f1cf6" } # P2WPKH (BIP-0084), electrum
                default           { $version_e = "043587cf" } # BIP-0044
            }
        }
        if ( $forceXpub ) {
            if ( -not $testnet ) {
                $version_e = "0488b21e"
            } else {
                $version_e = "043587cf"
            }
        }
        $depth_e = $this.Depth.ToString( "x2" )
        if ( $this.Parent ) {
            $pFingerprint_e = $this.Parent.FingerPrint
        } else {
            $pFingerprint_e = "00000000"
        }
        $index_e     = $this.Index.ToString( "x8" )
        $chainCode_e = $this.Chaincode
        $publicKey_e = $this.PublicKey
        $serialized  = $version_e + $depth_e + $pFingerprint_e + $index_e + $chainCode_e + $publicKey_e
        return ( Base58Check_Encode $serialized )
    }

    [string] GetPublicKeyHash() {
        return ( Hash160 $this.PublicKey )
    }
    [string] GetPublicKeyHash_UC() {
        return ( Hash160 $this.PublicKeyUC )
    }

    [string] GetWIF( [bool]$testnet ) {
        if ( $this.PrivateKey ) {
            return GetWIF $this.PrivateKey -Testnet:$testnet
        } else {
            Write-Host "PrivateKey is unknown." -Fore Red
            return $null
        }
    }
    [string] GetWIF_UC( [bool]$testnet ) {
        if ( $this.PrivateKey ) {
            return GetWIF $this.PrivateKey -UnCompressed -Testnet:$testnet
        } else {
            Write-Host "PrivateKey is unknown." -Fore Red
            return $null
        }
    }

    [string] GetAddressP2PKH( [bool]$testnet ) {
        return GetAddressP2PKH $this.PublicKey -Testnet:$testnet
    }
    [string] GetAddressP2PKH_UC( [bool]$testnet ) {
        return GetAddressP2PKH $this.PublicKeyUC -Testnet:$testnet
    }

    [string] GetAddressP2SHP2WPKH( [bool]$testnet ) {
        return GetAddressP2SH-P2WPKH $this.PublicKey -Testnet:$testnet
    }

    [string] GetAddressP2WPKH( [bool]$testnet ) {
        return GetAddressP2WPKH $this.PublicKey -Testnet:$testnet
    }

    [string] GetAddressP2TR( [bool]$testnet ) {
        return GetAddressP2TR $this.PublicKey -Testnet:$testnet
    }

    [string] GetExtendedPrivateKey() { return $this.GetExtendedPrivateKey( $this.Testnet ) }
    [string] GetExtendedPublicKey()  { return $this.GetExtendedPublicKey( $this.Testnet )  }
    [string] GetWIF()                { return $this.GetWIF( $this.Testnet )                }
    [string] GetWIF_UC()             { return $this.GetWIF_UC( $this.Testnet )             }
    [string] GetAddressP2PKH()       { return $this.GetAddressP2PKH( $this.Testnet )       }
    [string] GetAddressP2PKH_UC()    { return $this.GetAddressP2PKH_UC( $this.Testnet )    }
    [string] GetAddressP2WPKH()      { return $this.GetAddressP2WPKH( $this.Testnet )      }
    [string] GetAddressP2SHP2WPKH()  { return $this.GetAddressP2SHP2WPKH( $this.Testnet )  }
    [string] GetAddressP2TR()        { return $this.GetAddressP2TR( $this.Testnet )        }
}


# other utility functions

function descsum_polymod( [int[]]$symbols ) {
    # Internal function that computes the descriptor checksum.
    $GENERATOR = [UInt64[]]@( 0xf5dee51989, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a, 0x644d626ffd )
    $chk = [UInt64]1
    foreach ( $value in $symbols ) {
        $top = $chk -shr 35
        $chk = ( ( $chk -band 0x7ffffffff ) -shl 5 ) -bxor $value
        0..4 | ? { ( $top -shr $_ ) -band 1 } | % { $chk = $chk -bxor $GENERATOR[$_] }
    }
    return $chk
}

function descsum_expand( [string]$s ) {
    # Internal function that does the character to symbol expansion
    $INPUT_CHARSET = '0123456789()[],''/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#"\ '
    $groups  = [List[int]]::new()
    $symbols = [List[int]]::new()
    foreach ( $c in $s.GetEnumerator() ) {
        $v = $INPUT_CHARSET.IndexOf( $c )
        if ( $v -eq -1 ) { return $null }
        $symbols.Add( $v -band 31 )
        $groups.Add( $v -shr 5 )
        if ( $groups.Count -eq 3 ) {
            $symbols.Add( $groups[0] * 9 + $groups[1] * 3 + $groups[2] )
            $groups.Clear()
        }
    }
    if ( $groups.Count -eq 1 ) {
        $symbols.Add( $groups[0] )
    } elseif ( $groups.Count -eq 2 ) {
        $symbols.Add( $groups[0] * 3 + $groups[1] )
    }
    return $symbols.ToArray()
}

function descsum_check {
    param( [Parameter(ValueFromPipeline=$True)][string]$s )
    # Verify that the checksum is correct in a descriptor
    $CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    if ( $s[-9] -ne "#" ) { return $false }
    foreach ( $i in -8..-1 ) {
        if ( -not $CHECKSUM_CHARSET.Contains( $s[$i] ) ) { return $false }
    }
    $without = $s.Substring( 0, $s.Length - 9 )
    $symbols = ( descsum_expand $without ) + ( -8..-1 | % { $CHECKSUM_CHARSET.IndexOf( $s[$_] ) } )
    return ( descsum_polymod  $symbols ) -eq 1
}

function descsum_create {
    param( [Parameter(ValueFromPipeline=$True)][string]$s )
    # Add a checksum to a descriptor without
    $CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    $symbols  = ( descsum_expand $s ) + @( 0, 0, 0, 0, 0, 0, 0, 0 )
    $chk = ( descsum_polymod $symbols ) -bxor 1
    $checksum  = ( 0..7 | % { $CHECKSUM_CHARSET[ ( $chk -shr (5 * (7 - $_)) ) -band 31 ] } ) -join ""
    return $s + "#" + $checksum
}

