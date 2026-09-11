# Tests

The suites cover normal behavior, boundary conditions, invalid inputs, and conformance to published specifications.
They run offline without Pester, Python, or Go. Python and Go are only needed to regenerate reference data.

## Running tests

Run from the repository root in a fresh PowerShell session:

```powershell
./tests/Run-Tests.ps1
./tests/Run-Tests.ps1 -Suite 'Transactions*'
./tests/Run-Tests.ps1 -PowerShellPath 'C:\Program Files\PowerShell\7\pwsh.exe'
```

By default, the runner uses the current PowerShell executable for child processes.
Each `*.Tests.ps1` suite runs in a separate process to isolate PowerShell classes, `Add-Type`,
function replacements, and the fixed-base multiplication cache. The wallet under test is `BitcoinWallet.ps1`.

Results are written to `tests/results/<run-id>/`. `summary.json` contains the overall results;
each suite's JSON contains test names, outcomes, durations, and errors. `.log` files capture standard output and standard error.
The results directory is excluded from Git.

Failures, timeouts, loading errors, missing result files, and empty suites produce exit code 1.
The runner continues with the remaining suites after a failure. The default timeout is 300 seconds per suite;
use an option such as `-TimeoutSeconds 600` for slower environments.

## Benchmarking examples 01–07

```powershell
./tests/Benchmark-Examples.ps1 -Repetitions 3
```

The benchmark measures initial table generation and loading a saved table in separate processes, run sequentially.
It also measures a second execution in each process to compare memory cache reuse.
Only example execution is timed, and all output is checked against the `.out` snapshots.
Raw measurements are saved under `tests/results/`.

To compare implementations, specify a directory containing the baseline source files.
The wallet must be named `BitcoinWallet.ps1` in both source directories.

```powershell
./tests/Benchmark-GeneratorVariants.ps1 -BaselineRoot 'C:\path\to\baseline' -Repetitions 3
```

## Coverage

| Area | Checks | Suite |
|---|---|---|
| Bytes, integers, and encoding | All 256 byte values, pipeline aggregation, `i2h` options, 32/64-bit boundaries, CompactSize, PUSHDATA, ScriptNum, descriptor checksums | Encoding |
| BIP39 and PBKDF2 | 24 English and 24 Japanese published vectors, all five entropy lengths, checksums, unknown words, word counts, NFKD, whitespace, TREZOR seeds and extended keys, RFC6070 | Mnemonic |
| BIP32 and HDWallet | All 17 nodes in published vectors 1–4, 16 invalid keys in vector 5, public-only derivation, maximum index and depth, networks, SLIP formats, caching, disposal | HDWallet |
| Rare derivation conditions | HMAC substitution for IL=0, IL>=n, zero child keys, points at infinity, candidate skipping, and index exhaustion | DerivationFaults |
| Elliptic curves and hashes | Point addition and doubling, arbitrary base points, negative scalars, points at infinity, Jacobian normalization, inverses, independent hash expectations | CurveAndHash |
| Keys and addresses | Five private scalars on both networks, compressed/uncompressed WIF, eight address and output script types, all 23 BIP350 address examples, BIP86, Taproot tweaks, URIs | Addresses |
| Transactions | TXin/TXout/Witness/TX/TXS/DER serialization, independent parsing, invalid structures, MAX_MONEY and dust boundaries | Transactions |
| Signature hashes | 14 published BIP143 preimages, published BIP341 key-path examples, 68 independently generated cases covering six Segwit flags and seven Taproot flags with input, annex, and extension variations | Transactions |
| Signatures | Independent RFC6979/ECDSA expectations, independent verification of randomized ECDSA and Schnorr signatures, verifier checks against valid and invalid BIP340 vectors | Signatures |
| Messages | Fixed signatures, empty and Japanese messages, 252/253/65536-byte boundaries, tampering, both networks, address types, Electrum and custom Taproot extensions | Signatures |
| Transaction builders | Legacy/P2SH/Segwit/Taproot key-path and script-path spending on both networks, multiple inputs, selection order, amounts, change, memos, locktime, signature verification, insufficient funds, dust, incorrect keys, Nulldata, CLTV | Builders |
| Network boundaries | Mocked HTTP, confirmed UTXO filtering, ordering and scripts, network-specific URLs, empty/single responses, retries, exhaustion, balance service fallback | Network |
| Pipelines | Multiple and repeated inputs, output count and order, empty pipelines, early returns, chained conversions, mixed address formats and networks, URI options | Pipeline / Network |
| SeedQR | Standard and compact payloads for all 48 English/Japanese vectors, entropy, checksums, ECC options, invalid mnemonics | SeedQR |
| aezeed | LND/btcd reference data, passphrases, authentication, Unicode, versions, corruption, BIP39 confusion and coexistence | Aezeed |
| Examples | Output snapshots for all examples except 08, including spaces, blank lines, and final newlines; example 99 source references, IL constants, and recovered keys | Examples |
| Fixed-base cache | Lazy generation, binary format, loading in another process without generation, memory reuse, regeneration after corruption, continued operation when writes fail | GeneratorCache |
| Test harness | Assertion failure handling, fixture SHA256 values, official vector counts | Harness |

Suites use the shared `Test` and `Assert-*` helpers in `TestSupport.ps1`.
`AssertBitcoinAddress`, `GetTweak`, `Base58Address_Decode`, and `ConvertAddressToScriptPubKey`
accept explicit arguments only; their behavior is covered by the functional suites.

### Example snapshots

`Examples.Tests.ps1` automatically discovers `examples/*.ps1`, excluding example 08.
It combines standard output with `Write-Host` output, normalizes line endings to LF, and compares the result strictly with `.out`.
Spaces, tabs, blank lines, and final newlines are preserved. Snapshots use UTF-8 without a BOM and LF line endings.

For example 99, the suite inserts a conditional `Write-Host $il` into a temporary wallet copy.
It checks that the line referenced in the comment points to the specified code inside `HDWallet.Derive()`,
that the `$i` and `$ii` constants and output-order descriptions match the actual fifth and fourth values,
and that the recovered keys are correct. The source wallet is not modified.

When an output change is intentional, regenerate the snapshots and review the diff:

```powershell
./tests/Update-ExampleSnapshots.ps1
```

Tests and CI do not update snapshots automatically.

## Expected values and independence

- `fixtures/manifest.json` records source URLs, retrieval dates, source and fixture SHA256 values, and extraction scope.
- Official vectors are bundled locally; test runs do not download them.
- `reference/generate-core-vectors.py` generates expected values using the Python standard library and independent affine coordinate arithmetic, without calling the PowerShell implementation.
- `ReferenceCrypto.cs` is an independent signature verifier for tests. It is not intended as a production cryptographic library.
- `TransactionSupport.ps1` independently parses serialized bytes. Builder signature checks also use the production signature hash functions, which are separately checked against official and independent vectors.
- `examples/*.out` captures behavior for regression checks; these snapshots do not establish specification conformance.

To update official vectors, download the source files and run:

```sh
python3 tests/reference/import-official-vectors.py <download-directory>
```

Regenerate independent data with:

```sh
python3 tests/reference/generate-core-vectors.py
```

Review and update the corresponding manifest SHA256 values as well.
Do not replace expected values by copying production implementation output.

Check the independent fixed-base table SHA256 with:

```sh
python3 tests/reference/generate-generator-table.py
```

## Limits

The tests do not prove coverage of every input or branch, or the security of the cryptographic implementation.
Line and branch coverage percentages are not measured. The following require separate validation:

- Live service availability and response changes, transaction acceptance and broadcasting by real nodes, and physical SATSCARD devices.
- QR image rendering and decoding, and Windows Forms interaction. The QR display function's pipeline processing is checked structurally.
- Arbitrary custom script execution. Builder APIs support scripts satisfied by a single signature and do not provide a general script interpreter.
- Randomness quality, timing attacks, secret erasure from memory, and performance limits.

Example 08 requires a physical SATSCARD and is excluded from output comparisons.
CI is configured for Windows PowerShell 5.1, Windows PowerShell 7, and Linux PowerShell 7.
