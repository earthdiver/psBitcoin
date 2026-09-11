param([string]$SourceRoot = (Split-Path -Parent $PSScriptRoot), [string]$WalletFile = 'BitcoinWallet.ps1', [string]$ResultPath = '')
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
. (Join-Path $SourceRoot $WalletFile)
. (Join-Path $SourceRoot 'SeedQR.ps1')
# Capture the payload at the QR renderer boundary; no window or file is opened.
function QRCode {
    param($Payload,$ECCLevel,$Width,$Height)
    [pscustomobject]@{Payload=$Payload;ECCLevel=$ECCLevel;Width=$Width;Height=$Height}
}
$vectors=Read-Fixture 'bip39.json'
foreach ($lang in @('english','japanese')) {
    $japanese=$lang -eq 'japanese'; $index=0
    foreach ($v in $vectors.$lang) {
        Test "SeedQR payload $lang vector $index" {
            $words=@(GetValidatedMnemonicWords $v[1] -Japanese:$japanese)
            $qr=Mnemonic2QRCode $v[1] -Japanese:$japanese
            Assert-Equal $qr.Payload.Length ($words.Count*4)
            # Reconstruct bitstream from the decimal indices, independently hash entropy.
            $bits=-join ([regex]::Matches($qr.Payload,'\d{4}') | ForEach-Object { [Convert]::ToString([int]$_.Value,2).PadLeft(11,'0') })
            $entropyBits=$bits.Substring(0,$v[0].Length*4)
            $actual=-join ([regex]::Matches($entropyBits,'.{8}') | ForEach-Object { '{0:x2}' -f [Convert]::ToByte($_.Value,2) })
            Assert-Equal $actual $v[0]
            $sha=[Security.Cryptography.SHA256]::Create()
            try {
                $bytes=[byte[]]@([regex]::Matches($v[0],'..') | ForEach-Object {[Convert]::ToByte($_.Value,16)})
                $checksum=[Convert]::ToString($sha.ComputeHash($bytes)[0],2).PadLeft(8,'0').Substring(0,$bytes.Length/4)
                Assert-Equal $bits.Substring($v[0].Length*4) $checksum
            } finally { $sha.Dispose() }
            Assert-Equal $qr.ECCLevel 'M'; Assert-Equal $qr.Width 360; Assert-Equal $qr.Height 360
        }
        Test "CompactSeedQR exact entropy $lang vector $index" {
            $qr=Mnemonic2CompactQRCode $v[1] -Japanese:$japanese
            Assert-True ($qr.Payload -is [byte[]])
            Assert-Equal ([BitConverter]::ToString($qr.Payload).Replace('-','').ToLowerInvariant()) $v[0]
            Assert-Equal $qr.ECCLevel 'L'
        }
        $index++
    }
}
foreach ($bad in @('invalid', ('abandon '*12).Trim())) {
    Test "Invalid mnemonic cannot reach QR renderer <$bad>" {
        Assert-Throws { Mnemonic2QRCode $bad } 'mnemonic'
        Assert-Throws { Mnemonic2CompactQRCode $bad } 'mnemonic'
    }
}
Complete-TestSuite
