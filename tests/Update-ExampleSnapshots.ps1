# Explicit snapshot maintenance; never invoked by the test runner or CI.
param([string]$SourceRoot = (Split-Path -Parent $PSScriptRoot))
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
. (Join-Path $PSScriptRoot 'ExampleSupport.ps1')
$workspace=New-ExampleWorkspace $SourceRoot 'BitcoinWallet.ps1'
try {
    foreach ($example in (Get-DocumentedExamples $SourceRoot)) {
        $output=Get-ExampleOutput $workspace $example.BaseName
        $path=Join-Path $SourceRoot "examples/$($example.BaseName).out"
        [IO.File]::WriteAllText($path,$output,[Text.UTF8Encoding]::new($false))
        Write-Host "Updated $($example.BaseName).out"
    }
} finally { Remove-Item -LiteralPath $workspace -Recurse -Force }
