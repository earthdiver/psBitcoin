param([string]$SourceRoot = (Split-Path -Parent $PSScriptRoot), [string]$WalletFile = 'BitcoinWallet.ps1', [string]$ResultPath = '')
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
. (Join-Path $SourceRoot $WalletFile)
. (Join-Path $SourceRoot 'BitcoinTransaction.ps1')

Test 'All byte values: hex and binary encode/decode' {
    $bytes = [byte[]](0..255)
    $hex = -join (0..255 | ForEach-Object { '{0:x2}' -f $_ })
    $bits = -join (0..255 | ForEach-Object { [Convert]::ToString($_,2).PadLeft(8,'0') })
    Assert-Equal (i2h $bytes) $hex
    Assert-Equal ((h2i $hex) -join ',') ($bytes -join ',')
    Assert-Equal (i2b $bytes) $bits
    Assert-Equal ((b2i $bits) -join ',') ($bytes -join ',')
    Assert-Equal ($bytes | i2h) $hex
    Assert-Equal ($bytes | i2b) $bits
}
foreach ($case in @(
    @{ Options=@{First=2}; Want='0001' }, @{Options=@{Last=2}; Want='0405'},
    @{Options=@{First=1;Last=2}; Want='000405'}, @{Options=@{Skip=2;SkipLast=1};Want='020304'},
    @{Options=@{Reverse=$true};Want='050403020100'}, @{Options=@{First=1;PadLeft=6};Want='000000'},
    @{Options=@{Skip=6};Want=''}, @{Options=@{SkipLast=7};Want=''}
)) {
    Test "i2h options $($case.Options | ConvertTo-Json -Compress)" {
        $options=$case.Options
        Assert-Equal ([string](i2h ([byte[]](0..5)) @options)) $case.Want
    }
}
Test 'Empty and odd-length conversion contracts' {
    Assert-Equal @(i2h ([byte[]]@())).Count 0
    Assert-Equal @(h2i '').Count 0
    Assert-Equal (i2h (h2i 'f')) '0f'
    Assert-Equal (i2h (b2i '1')) '01'
    Assert-Throws { h2i 'gg' }
    Assert-Throws { b2i '12' }
}
foreach ($case in @(@(0,'00000000'),@(1,'01000000'),@(2147483648,'00000080'),@(4294967295,'ffffffff'))) {
    Test "UInt32 little endian $($case[0])" { Assert-Equal (UInt32toStr $case[0]) $case[1] }
}
foreach ($case in @(@('0','0000000000000000'),@('4294967296','0000000001000000'),@('18446744073709551615','ffffffffffffffff'))) {
    Test "UInt64 little endian $($case[0])" { Assert-Equal (UInt64toStr ([UInt64]$case[0])) $case[1] }
}
foreach ($case in @(@(0,'00'),@(251,'fb'),@(252,'fc'),@(253,'fdfd00'),@(254,'fdfe00'),@(65534,'fdfeff'),@(65535,'fdffff'),@(65536,'fe00000100'),@(65537,'fe01000100'),@(4294967295,'feffffffff'),@(4294967296,'ff0000000001000000'),@('18446744073709551615','ffffffffffffffffff'))) {
    Test "CompactSize boundary $($case[0])" { Assert-Equal (VarInttoStr ([UInt64]$case[0])) $case[1] }
}
foreach ($case in @(@(0,'00'),@(1,'01'),@(75,'4b'),@(76,'4c4c'),@(255,'4cff'),@(256,'4d0001'),@(65535,'4dffff'),@(65536,'4e00000100'))) {
    Test "Script push boundary $($case[0])" { Assert-Equal (Push ('ab' * $case[0])) ($case[1] + ('ab' * $case[0])) }
}
foreach ($case in @(@(0,''),@(1,'01'),@(127,'7f'),@(128,'8000'),@(255,'ff00'),@(256,'0001'),@(32767,'ff7f'),@(32768,'008000'),@(4294967295,'ffffffff00'))) {
    Test "ScriptNum boundary $($case[0])" { Assert-Equal (ConvertTo-ScriptNumHex $case[0]) $case[1] }
}
Test 'Length prefixes reject odd hex and count bytes' {
    Assert-Throws { Push 'a' } 'length'
    Assert-Throws { ConvertTo-CompactSizeHex 'a' } 'length'
    Assert-Equal (ConvertTo-CompactSizeHex '') '00'
    Assert-Equal (ConvertTo-CompactSizeHex ('00'*253)) ('fdfd00'+('00'*253))
}
Test 'Published descriptor checksum' {
    Assert-Equal (descsum_create 'raw(deadbeef)') 'raw(deadbeef)#89f8spxm'
    Assert-True (descsum_check 'raw(deadbeef)#89f8spxm')
}
foreach ($text in @('','raw(deadbeef)','raw(deadbeef)#','raw(deadbeef)#89f8spxmx','raw(deadbeef)#89f8spx','raw(deedbeef)#89f8spxm','raw(deedbeef)##9f8spxm',('raw('+[char]0xdc+')#00000000'))) {
    Test "Reject descriptor checksum <$text>" { Assert-False (descsum_check $text) }
}
Test 'Unknown descriptor characters cannot be encoded' { Assert-Throws { descsum_create ([string][char]0x3000) } 'character' }
Complete-TestSuite
