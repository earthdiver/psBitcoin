param(
    [Parameter(Mandatory=$true)][string]$Vectors,
    [string]$SourceRoot
)
$ErrorActionPreference = 'Stop'
if (-not $SourceRoot) {
    $SourceRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
}
Add-Type -Path (Join-Path $SourceRoot 'examples/Aezeed.cs')
$data = Get-Content -LiteralPath $Vectors -Raw -Encoding UTF8 | ConvertFrom-Json
function Bytes([string]$hex) {
    $a = [byte[]]::new($hex.Length / 2)
    for ($i=0; $i -lt $a.Length; $i++) { $a[$i] = [Convert]::ToByte($hex.Substring($i*2,2),16) }
    return ,$a
}
function Hex([byte[]]$a) { [BitConverter]::ToString($a).Replace('-','').ToLowerInvariant() }
$script:Checks = 0
function Equal($actual,$expected,$label) {
    if ($actual -cne $expected) { throw "Mismatch: $label" }
    $script:Checks++
}
function Reject([byte[]]$encoded,[byte[]]$password,$label) {
    $rejected = $false
    try { $null = [PsBitcoin.AezeedEntropyDecoder]::Decode($encoded,$password) }
    catch { $rejected = $_.Exception.Message -match 'passphrase or authentication tag' }
    Equal $rejected $true $label
}
$type = [PsBitcoin.AezeedEntropyDecoder]
$flags = [Reflection.BindingFlags]'Instance,NonPublic'
$extract = $type.GetMethod('Extract',$flags)
$decrypt = $type.GetMethod('DecryptTiny',$flags)
$scrypt = $type.GetMethod('Scrypt',$flags)
$i=0
foreach ($v in $data.Raw) {
    $d = [Activator]::CreateInstance($type,$true)
    try {
        [byte[]]$key = Bytes $v.Key
        Equal (Hex ($extract.Invoke($d,@(,$key)))) $v.Extracted "AEZ-Extract $i"
        Equal (Hex ($decrypt.Invoke($d,@($key,(Bytes $v.Encoded))))) $v.Plain "AEZ raw decipher $i"
    } finally { $d.Dispose() }
    $i++
}
"PASS: $i official C AEZ-Extract and raw decipher comparisons"
$i=0
foreach ($v in $data.EndToEnd) {
    [byte[]]$encoded = Bytes $v.Encoded
    [byte[]]$password = [Text.Encoding]::UTF8.GetBytes($v.Password)
    $effectivePassword = if ($password.Length) { $password } else { [Text.Encoding]::UTF8.GetBytes('aezeed') }
    $d = [Activator]::CreateInstance($type,$true)
    try {
        Equal (Hex ($scrypt.Invoke($d,@([byte[]]$effectivePassword,[byte[]]$encoded[24..28])))) $v.Key "OpenSSL scrypt $i"
    } finally { $d.Dispose() }
    Equal (Hex ([PsBitcoin.AezeedEntropyDecoder]::Decode($encoded,$password))) $v.Entropy "C-encrypted seed $i"
    Reject (Bytes $v.Tampered) $password "Ciphertext tampering with recomputed CRC $i"
    Reject (Bytes $v.ChangedSalt) $password "Salt tampering with recomputed CRC $i"
    Reject $encoded ([Text.Encoding]::UTF8.GetBytes('wrong-' + $v.Password)) "Wrong passphrase $i"
    $i++
    if (($i % 8) -eq 0) { "PASS: $i end-to-end cases (scrypt, entropy, three authentication failures each)" }
}
"PASS: $script:Checks total checks; archive SHA256 $($data.ArchiveSha256)"
