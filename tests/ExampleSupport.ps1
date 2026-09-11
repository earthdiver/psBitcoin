# Run documented examples in a disposable copy, including the edit requested by 99.
function New-ExampleWorkspace([string]$Root, [string]$Wallet) {
    $directory=Join-Path ([IO.Path]::GetTempPath()) ('psBitcoin-examples-'+[guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $directory
    try {
        foreach ($wordlist in @('wordlist.txt','wordlist_jp.txt')) {
            Copy-Item -LiteralPath (Join-Path $Root $wordlist) -Destination $directory
        }
        Copy-Item -LiteralPath (Join-Path $Root 'examples') -Destination $directory -Recurse
        $source=Get-Content -LiteralPath (Join-Path $Root $Wallet) -Raw -Encoding UTF8
        # Match the child derivation assignment, not the master-key assignment.
        $pattern='(?m)^(\s*\$il = \[bigint\]::new\( \$extendedKey\[31\.\.0\] \+ @\(0x00\) \))\s*$'
        $matches=[regex]::Matches($source,$pattern)
        if ($matches.Count -ne 1) { throw 'Expected exactly one child IL assignment for example 99 instrumentation' }
        $source=[regex]::Replace($source,$pattern,'$1'+"`n"+'                if ($global:PsBitcoinExampleTraceIL) { Write-Host $il }')
        [IO.File]::WriteAllText((Join-Path $directory 'BitcoinWallet.ps1'),$source,[Text.UTF8Encoding]::new($false))
        return $directory
    } catch { Remove-Item -LiteralPath $directory -Recurse -Force; throw }
}
function Get-ExampleOutput([string]$Workspace, [string]$ExampleName) {
    $previous=Get-Variable -Name PsBitcoinExampleTraceIL -Scope Global -ErrorAction SilentlyContinue
    $global:PsBitcoinExampleTraceIL=$ExampleName.StartsWith('99_')
    Push-Location $Workspace
    try {
        . (Join-Path $Workspace 'BitcoinWallet.ps1')
        $lines=@(& (Join-Path $Workspace "examples/$ExampleName.ps1") 6>&1 | ForEach-Object { [string]$_ })
        # Logical output lines have LF separators and a final newline on every OS.
        # Preserve all spaces, blank lines and embedded line breaks.
        return (($lines -join "`n") + "`n").Replace("`r`n","`n")
    } finally {
        Pop-Location
        if ($null -eq $previous) { Remove-Variable -Name PsBitcoinExampleTraceIL -Scope Global }
        else { $global:PsBitcoinExampleTraceIL=$previous.Value }
    }
}
function Get-DocumentedExamples([string]$Root) {
    Get-ChildItem -LiteralPath (Join-Path $Root 'examples') -Filter '*.ps1' |
        Where-Object { $_.BaseName -notlike '08_*' } | Sort-Object Name
}
