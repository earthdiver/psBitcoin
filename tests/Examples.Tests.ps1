param([string]$SourceRoot = (Split-Path -Parent $PSScriptRoot), [string]$WalletFile = 'BitcoinWallet.ps1', [string]$ResultPath = '')
. (Join-Path $PSScriptRoot 'TestSupport.ps1')
. (Join-Path $PSScriptRoot 'ExampleSupport.ps1')
$workspace=New-ExampleWorkspace $SourceRoot $WalletFile
$outputs=@{}
try {
    foreach ($example in (Get-DocumentedExamples $SourceRoot)) {
        Test "Documented example $($example.BaseName)" {
            $actual=Get-ExampleOutput $workspace $example.BaseName
            $outputs[$example.BaseName]=$actual
            $expected=Get-Content -LiteralPath (Join-Path $SourceRoot "examples/$($example.BaseName).out") -Raw -Encoding UTF8
            Assert-Equal $actual $expected 'Exact snapshot including spaces, blank lines and final LF'
        }
    }
    $special=Get-Content -LiteralPath (Join-Path $SourceRoot 'examples/99_Need-Help-Deriving-Extended-Private-Key.ps1') -Raw -Encoding UTF8
    Test 'Example 99 documented wallet line locates child IL assignment' {
        $lineMatch=[regex]::Match($special,'after line (\d+) of BitcoinWallet\.ps1')
        Assert-True $lineMatch.Success
        $codeMatch=[regex]::Match($special,'In HDWallet\.Derive\(\), locate: ([^\r\n]+)')
        Assert-True $codeMatch.Success
        $sourceLines=@(Get-Content -LiteralPath (Join-Path $SourceRoot 'BitcoinWallet.ps1') -Encoding UTF8)
        $line=[int]$lineMatch.Groups[1].Value
        Assert-True ($line -gt 0 -and $line -le $sourceLines.Count)
        Assert-Equal $sourceLines[$line-1].Trim() $codeMatch.Groups[1].Value
        $tokens=$null; $errors=$null
        $ast=[Management.Automation.Language.Parser]::ParseInput(($sourceLines -join "`n"),[ref]$tokens,[ref]$errors)
        $method=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionMemberAst] -and $node.Name -eq 'Derive' -and $node.Extent.StartLineNumber -le $line -and $node.Extent.EndLineNumber -ge $line},$true)
        Assert-True ($null -ne $method) 'Referenced line must belong to Derive'
    }
    $trace=@($outputs['99_Need-Help-Deriving-Extended-Private-Key'] -split "`n")
    foreach ($case in @(@{Variable='i';Ordinal=5},@{Variable='ii';Ordinal=4})) {
        Test "Example 99 hardcoded IL and ordinal for $($case.Variable)" {
            $pattern='(?m)^\$'+$case.Variable+'\s*=\s*\[bigint\]::Parse\("(\d+)"\)\s*# the (\d+)(?:st|nd|rd|th) output of \$il'
            $match=[regex]::Match($special,$pattern)
            Assert-True $match.Success
            Assert-Equal ([int]$match.Groups[2].Value) $case.Ordinal
            Assert-Equal $match.Groups[1].Value $trace[$case.Ordinal-1] 'Constant must equal actual derivation IL'
        }
    }
    Test 'Example 99 recovered extended private key equals expected key' {
        $expected=@($trace | Where-Object { $_ -like 'expected: *' })
        $found=@($trace | Where-Object { $_ -like 'found   : *' })
        Assert-Equal $expected.Count 1; Assert-Equal $found.Count 1
        Assert-Equal $found[0].Substring(10) $expected[0].Substring(10)
    }
} finally { Remove-Item -LiteralPath $workspace -Recurse -Force }
Complete-TestSuite
