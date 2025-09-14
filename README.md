# psBitcoin

## Overview
This tool aims to help users understand bitcoin wallets in various forms, including entropy, mnemonic phrase, seed, extended keys, and more.

### Pros
- **No external libraries are required**: It leverages the pre-installed PowerShell in Windows, making it compatible with any PC running Windows 10. (The RIPEMD160 NuGet package is required for PowerShell 7.X, though.)

### Cons  (or perhaps even a Pro)
- Limited to bitcoin; does not support other cryptocurrencies.

### Notes
- **BitcoinWallet.ps1 does not access the network at all.**
- `GetBalance` and `GetUTXO` functions, along with the four other functions that call GetUTXO in BitcoinTransaction.ps1, connect to the Internet.
- For enhanced security, it is recommended to use the tool with the network disabled in Windows Sandbox, considering the risk of malware infection on your PC. Save the following code as a text file with the extension .wsb on your desktop, and double-click it to start the sandbox with the network disabled.


```NoNetwork.wsb
Configuration>
  <LogonCommand>
    <Command>powershell -Command "Set-ExecutionPolicy ByPass -Scope CurrentUser"</Command>
  </LogonCommand>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>C:\Users\{UserID}\Desktop\{Writable Folder}</HostFolder>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>C:\Users\{UserID}\Desktop\{ReadOnly Folder}</HostFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <Networking>Disable</Networking>
</Configuration>
```

## Operating Environment

The tool has been tested on a PC running Windows 10, in the following environment:
- Windows PowerShell 5.1
- PowerShell 7.X

## Setup
[For PowerShell 7 series only]
Obtain the RIPEMD160 NuGet package by executing the following command:

```
Install-Package RIPEMD160 -Source https://www.nuget.org/api/v2 -Scope CurrentUser    # Execute only once. 
```

> [!TIP]
> If RIPEMD160.dll is not found, the assembly will be loaded from the DLL image embedded within the script.

[For Windows PowerShell 5.1/PowerShell 7 series]
Execute the following command to load function/class definitions:

```powershell:
. ./BitcoinWallet.ps1
```

Please place the wordlists in the same folder.

> [!TIP]
> If you encounter an error stating "running script is disabled on this system" error, use `Set-ExecutionPolicy ByPass -Scope Process` to bypass the restriction.

## Running Examples

```powershell:
./examples/01_entropy2seed.ps1
./examples/02_seed2addresses.ps1
./examples/03_multisig.ps1
./examples/04_BrainWallet.ps1
./examples/05_HD-BrainWallet.ps1
./examples/06_nested-BIP85.ps1
./examples/07_SilentPaymentAddresses_BIP352.ps1
```

## Other Tools

- Functions (`RawTXfromLegacyAddress`,`RawTXfromSegwitAddress`,`RawTXfromTaprootAddress`, etc.) to generate TX data (experimental; use these on Testnet only)
- Functions (`Mnemonic2QRcode`, `Mnemonic2CompactQRcode`) to generate SeedQR images

```
. ./BitcoinTransaction.ps1
. ./SeedQR.ps1
```

## Donations

Welcome at the following addresses (buy me a coffee).
- `bc1qv6pe28gesk52zuj7fnqk4vul4x6qtyfc7qf9y4`
- `sp1qq08f39ntp6zv03exfx0he79nklvx9ulh436ygulgddgt26796274qqs5gqanfc8m5hmaecqz40l7uw4qp6ldj37q2lcv35azsegp3huhpclx8qsr`

## License

<p xmlns:cc="http://creativecommons.org/ns#" xmlns:dct="http://purl.org/dc/terms/"><span property="dct:title">psBitcoin</span> is licensed under <a href="https://creativecommons.org/licenses/by-sa/4.0/?ref=chooser-v1" target="_blank" rel="license noopener noreferrer" style="display:inline-block;">CC BY-SA 4.0<img style="height:22px!important;margin-left:3px;vertical-align:text-bottom;" src="https://mirrors.creativecommons.org/presskit/icons/cc.svg?ref=chooser-v1" alt=""><img style="height:22px!important;margin-left:3px;vertical-align:text-bottom;" src="https://mirrors.creativecommons.org/presskit/icons/by.svg?ref=chooser-v1" alt=""><img style="height:22px!important;margin-left:3px;vertical-align:text-bottom;" src="https://mirrors.creativecommons.org/presskit/icons/sa.svg?ref=chooser-v1" alt=""></a></p>
