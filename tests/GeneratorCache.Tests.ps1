param([string]$SourceRoot = (Split-Path -Parent $PSScriptRoot), [string]$WalletFile = 'BitcoinWallet.ps1', [string]$ResultPath = '')
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
. (Join-Path $SourceRoot $WalletFile)
$directory=Join-Path ([IO.Path]::GetTempPath()) ('psBitcoin-cache-test-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $directory
$previous=[Environment]::GetEnvironmentVariable('PSBITCOIN_GENERATOR_CACHE')
$env:PSBITCOIN_GENERATOR_CACHE=Join-Path $directory 'generator.bin'
$g=[ECDSA]::new()
$core=Read-Fixture 'core.json'
try {
    Test 'Import, trivial scalars and arbitrary bases do not create the table' {
        Assert-True ($null -eq [ECDSA]::GeneratorTable)
        $null=$g*[bigint]0; $null=$g*[bigint]1
        $null=($g+$g)*[bigint]3
        Assert-True ($null -eq [ECDSA]::GeneratorTable)
        Assert-False (Test-Path $env:PSBITCOIN_GENERATOR_CACHE)
    }
    Test 'First fixed-base multiplication generates a verified binary table' {
        Assert-Equal (GetPublicKey ('0'*63+'2')) $core.addresses[2].public
        Assert-Equal ([ECDSA]::GeneratorTable.Count) 256
        $data=[IO.File]::ReadAllBytes($env:PSBITCOIN_GENERATOR_CACHE)
        Assert-Equal $data.Length 16392
        Assert-True ([ECDSA]::IsGeneratorDataValid($data))
        Assert-Equal ([Text.Encoding]::ASCII.GetString($data,0,8)) 'PSBG0001'
    }
    Test 'Low byte covers every value and its transition to bit eight' {
        $expected=$null
        for ($scalar=0;$scalar -le 511;$scalar++) {
            $actual=$g*[bigint]$scalar
            if ($scalar -eq 0) { Assert-True ($null -eq $actual) }
            else {
                Assert-Equal $actual.X $expected.X "X for scalar $scalar"
                Assert-Equal $actual.Y $expected.Y "Y for scalar $scalar"
            }
            $expected=$expected+$g
        }
    }
    Test 'Each high bit combines correctly with low-byte boundaries' {
        $high=$g
        for ($bit=0;$bit -lt 256;$bit++) {
            if ($bit -ge 8) {
                foreach ($low in @(0,1,127,128,254,255)) {
                    $expected=$high+($g*[bigint]$low)
                    $actual=$g*(([bigint]::One -shl $bit)+$low)
                    Assert-Equal $actual.X $expected.X "X for bit $bit low $low"
                    Assert-Equal $actual.Y $expected.Y "Y for bit $bit low $low"
                }
            }
            $high=$high+$high
        }
    }
    Test 'Scalar order and signed normalization preserve low-byte selection' {
        foreach ($delta in @(-257,-256,-255,-1,0,1,255,256,257)) {
            $actual=$g*([ECDSA]::Order+$delta)
            $expected=$g*[bigint]$delta
            if ($delta -eq 0) { Assert-True ($null -eq $actual) }
            else { Assert-Equal $actual.X $expected.X; Assert-Equal $actual.Y $expected.Y }
        }
    }
    $valid=[IO.File]::ReadAllBytes($env:PSBITCOIN_GENERATOR_CACHE)
    Test 'Subsequent multiplications retain memory even if disk cache disappears' {
        $table=[ECDSA]::GeneratorTable
        Remove-Item $env:PSBITCOIN_GENERATOR_CACHE
        Assert-Equal (GetPublicKey ('0'*63+'3')) $core.addresses[4].public
        Assert-True ([object]::ReferenceEquals($table,[ECDSA]::GeneratorTable))
        Assert-False (Test-Path $env:PSBITCOIN_GENERATOR_CACHE)
    }
    Test 'Fresh process loads the disk table without invoking generation' {
        [IO.File]::WriteAllBytes($env:PSBITCOIN_GENERATOR_CACHE,$valid)
        $source=Get-Content (Join-Path $SourceRoot $WalletFile) -Raw
        $source=$source.Replace('hidden static [ECDSAJ[]] GenerateGeneratorTable() {',"hidden static [ECDSAJ[]] GenerateGeneratorTable() {`n        if ( `$env:PSBITCOIN_GENERATOR_CACHE ) { throw 'Generation must not run when cache is valid' }")
        $copy=Join-Path $directory 'LoadOnly.ps1'
        [IO.File]::WriteAllText($copy,$source,[Text.UTF8Encoding]::new($false))
        $command="`$ErrorActionPreference='Stop'; . '"+$copy.Replace("'","''")+"'; GetPublicKey ('0'*63+'2')"
        $info=[Diagnostics.ProcessStartInfo]::new()
        $info.FileName=(Get-Process -Id $PID).Path
        $info.Arguments='-NoProfile -NonInteractive -OutputFormat Text -ExecutionPolicy Bypass -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
        $info.UseShellExecute=$false; $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
        $process=[Diagnostics.Process]::new(); $process.StartInfo=$info
        try {
            $null=$process.Start(); $out=$process.StandardOutput.ReadToEndAsync(); $err=$process.StandardError.ReadToEndAsync()
            if (-not $process.WaitForExit(30000)) { $process.Kill(); throw 'Cache loading process timed out' }
            Assert-Equal $process.ExitCode 0 $err.Result
            Assert-Equal $out.Result.Trim() $core.addresses[2].public
        } finally { $process.Dispose() }
        Assert-Equal ([IO.File]::ReadAllBytes($env:PSBITCOIN_GENERATOR_CACHE) -join ',') ($valid -join ',')
    }
    foreach ($corruption in @('truncated','header','coordinate','oversized','v2-format')) {
        Test "Invalid $corruption cache is regenerated" {
            $data=[byte[]]$valid.Clone()
            switch ($corruption) {
                'truncated' { $data=[byte[]](1,2,3) }
                'header' { $data[0]=0 }
                'coordinate' { $data[100]=$data[100] -bxor 1 }
                'v2-format' { $data=[byte[]]::new(32200); [Array]::Copy([Text.Encoding]::ASCII.GetBytes('PSBG0002'),$data,8) }
                'oversized' { $data=[byte[]]::new(16393) }
            }
            [IO.File]::WriteAllBytes($env:PSBITCOIN_GENERATOR_CACHE,$data)
            [ECDSA]::GeneratorTable=$null
            Assert-Equal (GetPublicKey ('0'*63+'2')) $core.addresses[2].public
            Assert-True ([ECDSA]::IsGeneratorDataValid([IO.File]::ReadAllBytes($env:PSBITCOIN_GENERATOR_CACHE)))
            Assert-Equal @(Get-ChildItem $directory -Filter '*.tmp').Count 0
        }
    }
    Test 'Unwritable cache path falls back to a retained memory table' {
        $env:PSBITCOIN_GENERATOR_CACHE=Join-Path (Join-Path $directory 'generator.bin') 'impossible.bin'
        [ECDSA]::GeneratorTable=$null
        Assert-Equal (GetPublicKey ('0'*63+'2')) $core.addresses[2].public
        $table=[ECDSA]::GeneratorTable
        Assert-Equal (GetPublicKey ('0'*63+'3')) $core.addresses[4].public
        Assert-True ([object]::ReferenceEquals($table,[ECDSA]::GeneratorTable))
    }
} finally {
    [ECDSA]::GeneratorTable=$null
    [Environment]::SetEnvironmentVariable('PSBITCOIN_GENERATOR_CACHE',$previous)
    Remove-Item $directory -Recurse -Force
}
Complete-TestSuite
