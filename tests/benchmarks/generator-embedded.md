# Embedded generator table comparison

Serial fresh Windows processes; three trials with rotating scenario order; wallet import and example execution timed separately; process startup excluded. All first/repeat outputs checked against .out. Files copied to Windows temporary directories before measurement. OS caches are not flushed. Engines measured sequentially without concurrent test runs.

Times below are milliseconds. Each cell is the median of three measurements.
First-use totals are calculated per trial as wallet import + first example execution, then reduced to the median.
The process executable startup time is excluded. Small differences with three samples should not be treated as a reliable speedup.

Examples 01 and 05 do not initialize the generator table in any scenario.
The mode names for these examples describe the cache setup only; they do not imply actual generation or loading.

## PowerShell 5.1.26100.9444

OS: Microsoft Windows NT 10.0.26200.0; processor: Intel64 Family 6 Model 189 Stepping 1, GenuineIntel

### First use, including wallet import

| Example | External: generate | External: load | Embedded |
|---|---:|---:|---:|
| 01_entropy2seed | 648.2 | 671.7 | 651.0 |
| 02_seed2addresses | 1694.2 | 1620.9 | 1613.5 |
| 03_multisig | 2019.9 | 1976.6 | 1936.1 |
| 04_BrainWallet | 684.7 | 640.7 | 586.3 |
| 05_HD-BrainWallet | 1160.3 | 1133.2 | 1140.9 |
| 06_nested-BIP85 | 1301.3 | 1256.0 | 1222.0 |
| 07_SilentPaymentAddresses_BIP352 | 1425.1 | 1356.2 | 1377.4 |

### Second execution in the same process

| Example | External after generation | External after loading | Embedded |
|---|---:|---:|---:|
| 01_entropy2seed | 31.3 | 31.8 | 31.8 |
| 02_seed2addresses | 439.6 | 436.5 | 441.0 |
| 03_multisig | 618.6 | 639.3 | 630.6 |
| 04_BrainWallet | 24.7 | 23.9 | 48.0 |
| 05_HD-BrainWallet | 532.2 | 516.3 | 537.5 |
| 06_nested-BIP85 | 379.5 | 371.8 | 366.8 |
| 07_SilentPaymentAddresses_BIP352 | 306.9 | 301.2 | 311.5 |

Wallet import alone, pooled median across scenarios and examples: baseline 293.5 ms, candidate 296.4 ms.

## PowerShell 7.6.5

OS: Microsoft Windows NT 10.0.26200.0; processor: Intel64 Family 6 Model 189 Stepping 1, GenuineIntel

### First use, including wallet import

| Example | External: generate | External: load | Embedded |
|---|---:|---:|---:|
| 01_entropy2seed | 773.4 | 776.7 | 770.9 |
| 02_seed2addresses | 1817.8 | 1654.5 | 1648.0 |
| 03_multisig | 2063.5 | 1972.8 | 2026.1 |
| 04_BrainWallet | 829.3 | 788.9 | 733.7 |
| 05_HD-BrainWallet | 1292.1 | 1292.5 | 1307.2 |
| 06_nested-BIP85 | 1318.6 | 1261.9 | 1240.4 |
| 07_SilentPaymentAddresses_BIP352 | 1444.3 | 1379.4 | 1342.1 |

### Second execution in the same process

| Example | External after generation | External after loading | Embedded |
|---|---:|---:|---:|
| 01_entropy2seed | 36.1 | 40.0 | 36.8 |
| 02_seed2addresses | 444.4 | 448.9 | 447.5 |
| 03_multisig | 664.5 | 651.4 | 679.9 |
| 04_BrainWallet | 31.6 | 49.1 | 26.6 |
| 05_HD-BrainWallet | 301.4 | 331.1 | 355.2 |
| 06_nested-BIP85 | 337.2 | 343.6 | 368.5 |
| 07_SilentPaymentAddresses_BIP352 | 277.3 | 258.8 | 274.5 |

Wallet import alone, pooled median across scenarios and examples: baseline 451.6 ms, candidate 457.8 ms.

## Interpretation

For the five examples that initialize the table (02, 03, 04, 06, 07), the sum of first-use medians is:

| PowerShell | External: generate | External: load | Embedded | Reduction vs generation | Reduction vs loading |
|---|---:|---:|---:|---:|---:|
| 5.1 | 7125.2 ms | 6850.4 ms | 6735.3 ms | 5.5% | 1.7% |
| 7 | 7473.5 ms | 7057.5 ms | 6990.3 ms | 6.5% | 1.0% |

These are sums of per-example medians, not the duration of one combined workload.
The improvement over saved-file loading is small and varies by example.
Repeated execution is not uniformly faster: for example, PowerShell 5.1 example 04
increases from 23.9 ms after external loading to 48.0 ms with the embedded table.
The same table array is reused; the cause of the timing difference is not established.

The main simplification is removal of runtime table generation and external cache management.
Total source size increases by 159 lines and 27,911 bytes because the constants occupy 256 lines.

## Source size

| | Lines | Bytes |
|---|---:|---:|
| baseline | 1689 | 77140 |
| candidate | 1848 | 105051 |

The embedded version stores one X/Y pair per line as a static string.
The first nontrivial generator multiplication parses the coordinates; subsequent calls reuse the same array.
External file handling and runtime point generation are removed.

## Validation

Both Windows PowerShell 5.1 and PowerShell 7 pass all 982 tests in 16 suites.
The table digest covers all 256 X/Y pairs and matches the independent affine generator.
Examples 01–07, 09, and 99 pass snapshot checks; example 99 also passes its source-line and IL checks.
The benchmarks verify 252 example executions (2 engines × 3 trials × 7 examples × 3 scenarios × 2 phases).

## Reproduction

Baseline source: commit `2c4da5d`, stored in a separate directory with its wordlists and examples.

```powershell
./tests/Benchmark-GeneratorVariants.ps1 -BaselineRoot 'C:\path\to\baseline' -Repetitions 3
```

[Raw measurements and source hashes](generator-embedded.json).
