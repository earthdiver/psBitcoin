# Independent byte parser for assertions, not the production ToString serializers.
if (-not ('TestCrypto' -as [type])) {
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Add-Type -Path (Join-Path $PSScriptRoot 'ReferenceCrypto.cs') -ReferencedAssemblies System.Numerics
    } else { Add-Type -Path (Join-Path $PSScriptRoot 'ReferenceCrypto.cs') }
}
function Read-TestCompactSize($Reader) {
    $prefix=$Reader.ReadByte()
    switch ($prefix) {
        253 { return $Reader.ReadUInt16() }
        254 { return $Reader.ReadUInt32() }
        255 { return $Reader.ReadUInt64() }
        default { return [UInt64]$prefix }
    }
}
function Read-TestHex($Reader, [int]$Count) {
    $bytes=$Reader.ReadBytes($Count)
    if ($bytes.Length -ne $Count) { throw 'Truncated transaction' }
    return [TestCrypto]::Hex($bytes)
}
function Read-TestField($Reader) { Read-TestHex $Reader (Read-TestCompactSize $Reader) }
function Read-TestTransaction([string]$Hex) {
    $stream=[IO.MemoryStream]::new([TestCrypto]::Bytes($Hex))
    $reader=[IO.BinaryReader]::new($stream)
    try {
        $version=$reader.ReadUInt32()
        $count=Read-TestCompactSize $reader
        $witness=$count -eq 0
        if ($witness) {
            Assert-Equal $reader.ReadByte() 1
            $count=Read-TestCompactSize $reader
        }
        $inputs=@(for ($i=0;$i -lt $count;$i++) {
            $id=$reader.ReadBytes(32); [Array]::Reverse($id)
            [pscustomobject]@{Txid=[TestCrypto]::Hex($id); Index=$reader.ReadUInt32(); Script=(Read-TestField $reader); Sequence=$reader.ReadUInt32()}
        })
        $count=Read-TestCompactSize $reader
        $outputs=@(for ($i=0;$i -lt $count;$i++) {
            [pscustomobject]@{Value=$reader.ReadUInt64(); Script=(Read-TestField $reader)}
        })
        $stacks=@(if ($witness) { foreach ($txInput in $inputs) {
            $n=Read-TestCompactSize $reader
            $items=@(for ($i=0;$i -lt $n;$i++) { Read-TestField $reader })
            [pscustomobject]@{Items=$items}
        } })
        $locktime=$reader.ReadUInt32()
        Assert-Equal $stream.Position $stream.Length 'No trailing bytes'
        return [pscustomobject]@{Version=$version; Inputs=$inputs; Outputs=$outputs; Witness=$witness; Stacks=$stacks; Locktime=$locktime}
    } finally { $reader.Dispose(); $stream.Dispose() }
}
function ConvertTo-TestTXS($Parsed) {
    $inputs=[TXin[]]@($Parsed.Inputs | ForEach-Object { [TXin]::new($_.Txid,$_.Index,$_.Script,$_.Sequence) })
    $outputs=[TXout[]]@($Parsed.Outputs | ForEach-Object { [TXout]::new($_.Value,$_.Script) })
    $witnesses=[Witness[]]@($inputs | ForEach-Object { [Witness]::new() })
    return [TXS]::new($Parsed.Version,0,1,$inputs,$outputs,$witnesses,$Parsed.Locktime)
}
