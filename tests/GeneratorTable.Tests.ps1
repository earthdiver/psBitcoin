param([string]$SourceRoot = (Split-Path -Parent $PSScriptRoot), [string]$WalletFile = 'BitcoinWallet.ps1', [string]$ResultPath = '')
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
. (Join-Path $SourceRoot $WalletFile)
$g=[ECDSA]::new()
$core=Read-Fixture 'core.json'
try {
    Test 'Import, trivial scalars and arbitrary bases do not initialize the table' {
        Assert-True ($null -eq [ECDSA]::GeneratorTable)
        $null=$g*[bigint]0; $null=$g*[bigint]1
        $null=($g+$g)*[bigint]3
        Assert-True ($null -eq [ECDSA]::GeneratorTable)
    }
    $rows=@([Secp256k1GeneratorData]::Coordinates -split '\r?\n')
    Test 'First fixed-base multiplication initializes exactly 256 coordinate pairs' {
        Assert-Equal $rows.Count 256
        Assert-Equal (GetPublicKey ('0'*63+'2')) $core.addresses[2].public
        Assert-Equal ([ECDSA]::GeneratorTable.Count) 256
    }
    # Independent affine doubling, without production curve or modular-inverse methods.
    $prime=[bigint]::Pow(2,256)-[bigint]::Pow(2,32)-977
    $referenceX=[bigint]::Parse('079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798','AllowHexSpecifier')
    $referenceY=[bigint]::Parse('0483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8','AllowHexSpecifier')
    $reference=[Collections.Generic.List[object]]::new()
    for ($index=0;$index -lt 256;$index++) {
        Test "Generator point 2^$index G: stored X/Y, initialized point and multiplication" {
            Assert-True ($rows[$index] -cmatch '^[0-9a-f]{64} [0-9a-f]{64}$') "Coordinate format at index $index"
            $expectedX=$referenceX.ToString('x').TrimStart('0').PadLeft(64,'0')
            $expectedY=$referenceY.ToString('x').TrimStart('0').PadLeft(64,'0')
            Assert-Equal $rows[$index] ($expectedX+' '+$expectedY) "Stored X/Y at index $index"
            $point=[ECDSA]::GeneratorTable[$index]
            Assert-Equal $point.X $referenceX "Initialized X at index $index"
            Assert-Equal $point.Y $referenceY "Initialized Y at index $index"
            Assert-Equal $point.Z ([bigint]::One)
            $actual=$g*([bigint]::One -shl $index)
            Assert-Equal $actual.X $referenceX "Multiplication X at index $index"
            Assert-Equal $actual.Y $referenceY "Multiplication Y at index $index"
        }
        $reference.Add(@($referenceX,$referenceY))
        $slope=(3*$referenceX*$referenceX*[bigint]::ModPow(2*$referenceY,$prime-2,$prime))%$prime
        $nextX=(($slope*$slope-2*$referenceX)%$prime+$prime)%$prime
        $referenceY=(($slope*($referenceX-$nextX)-$referenceY)%$prime+$prime)%$prime
        $referenceX=$nextX
    }
    Test 'Sparse and dense scalars combine independently verified points' {
        foreach ($hex in @('3','f','8000000000000001','10000000000000001',('55'*32),('aa'*32),'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140')) {
            $scalar=[bigint]::Parse('0'+$hex,'AllowHexSpecifier')
            $expected=$null
            for ($bit=0;$bit -lt 256;$bit++) {
                if (($scalar -band ([bigint]::One -shl $bit)) -ne 0) {
                    $expected=$expected+[ECDSA]::new($reference[$bit][0],$reference[$bit][1])
                }
            }
            $actual=$g*$scalar
            Assert-Equal $actual.X $expected.X "X for scalar $hex"
            Assert-Equal $actual.Y $expected.Y "Y for scalar $hex"
        }
    }
    Test 'Subsequent multiplications reuse the same memory table' {
        $table=[ECDSA]::GeneratorTable
        Assert-Equal (GetPublicKey ('0'*63+'3')) $core.addresses[4].public
        Assert-True ([object]::ReferenceEquals($table,[ECDSA]::GeneratorTable))
    }
} finally { [ECDSA]::GeneratorTable=$null }
Complete-TestSuite
