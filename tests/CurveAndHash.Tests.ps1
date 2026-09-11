param([string]$SourceRoot = (Split-Path -Parent $PSScriptRoot), [string]$WalletFile = 'BitcoinWallet.ps1', [string]$ResultPath = '')
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
. (Join-Path $SourceRoot $WalletFile)
. (Join-Path $SourceRoot 'BitcoinTransaction.ps1')
$core=Read-Fixture 'core.json'
$g=[ECDSA]::new()
Test 'Affine doubling and addition agree with independent point vectors' {
    $two=$g+$g; $three=$two+$g
    Assert-Equal $two.X.ToHexString64() $core.addresses[2].public.Substring(2)
    Assert-Equal $three.X.ToHexString64() $core.addresses[4].public.Substring(2)
    Assert-Equal ('04'+$two.X.ToHexString64()+$two.Y.ToHexString64()) $core.addresses[2].uncompressed
}
Test 'Scalar zero, order, negative and wrapping' {
    Assert-True ($null -eq ($g*[bigint]0))
    Assert-True ($null -eq ($g*[ECDSA]::Order))
    $neg=$g*[bigint](-1)
    Assert-Equal $neg.X $g.X
    Assert-Equal $neg.Y ([ECDSA]::p-$g.Y)
    Assert-True ($null -eq ($g+$neg))
    Assert-Equal ($g*([ECDSA]::Order+[bigint]1)).X $g.X
    Assert-Equal ([ECDSA]::op_Addition($null,$g)).X $g.X
    Assert-Equal ([ECDSA]::op_Addition($g,$null)).X $g.X
}
Test 'Arbitrary-base multiplication and Jacobian normalization' {
    $two=$g*[bigint]2
    $six=$two*[bigint]3
    Assert-Equal $six.X ($g*[bigint]6).X
    Assert-Equal $six.Y ($g*[bigint]6).Y
    $j=[ECDSAJ]::new(($g.X*4)%[ECDSA]::p,($g.Y*8)%[ECDSA]::p,[bigint]2)
    $point=[ECDSA]::new($j)
    Assert-Equal $point.X $g.X; Assert-Equal $point.Y $g.Y
    Assert-True ([ECDSA]::new([ECDSAJ]::new(1,1,0))).Err
    Assert-True ([ECDSA]::new(0,0)).Err
}
foreach ($modulus in @([ECDSA]::p,[ECDSA]::Order,[bigint]101)) {
    foreach ($value in @([bigint]1,[bigint]2,[bigint](-3),($modulus+[bigint]7))) {
        Test "Modular inverse m=$modulus a=$value" {
            $inverse=[ECDSA]::ModInv($value,$modulus)
            Assert-Equal (((($value*$inverse)%$modulus)+$modulus)%$modulus) 1
        }
    }
}
Test 'Hashes match fixed independent fixtures' {
    Assert-Equal (Hash160 $core.addresses[0].public) '751e76e8199196d454941c45d1b3a323f1433bd6'
    foreach ($v in $core.ecdsa) { Assert-Equal (Hash256 $v.data) $v.digest }
}
foreach ($bad in @('','g0','abc')) {
    Test "Hash API rejects invalid input <$bad>" {
        Assert-Throws { Hash160 $bad }
        Assert-Throws { Hash256 $bad }
        Assert-Throws { HashTR 'TapTweak' $bad }
    }
}
Complete-TestSuite
