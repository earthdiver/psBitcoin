# 新しいテストで検出した問題

2026-09-11。今回の変更はテスト整備を対象としており、ウォレット/トランザクション本体は変更していません。
次のテストは本体の修正が入るまで失敗することを意図しています。
既知失敗の除外・skip・成功扱いは設けておらず、実行器とCIも非ゼロで終了します。

## 複数パイプライン入力の欠落

`ValueFromPipeline` を指定した関数のうち、下記は複数の入力を渡すと最後の入力だけを処理します。
`process` ブロックがなく、各入力に対する処理が実行されません。

```powershell
. ./BitcoinWallet.ps1
@('00', '01') | Hash256                 # 実際は1件
@('00', '01') | ForEach-Object { Hash256 $_ }  # 期待する2件
```

`Pipeline.Tests.ps1` の30ケースと `Network.Tests.ps1` の2ケースで検出します。
通常版・Fast版、Windows PowerShell 5.1・PowerShell 7で確認します。

- `h2i`, `b2i`, `Hash160`, `Hash256`
- `GetPublicKey`, `GetPublicKeyFromWIF`, `DecompressPublicKey`, `GetWIF`
- `Base58Check_Encode`, `Base58Check_Decode`, `Base58Address_Decode`
- `Bech32_Encode`, `Bech32_Decode`, `AssertBitcoinAddress`
- `GetTweak`, `GetTweakedWIF`, `GetURI`, `ConvertAddressToScriptPubKey`
- `descsum_create`, `descsum_check`
- `GetAddressP2PKH`, `GetAddressP2SH`, `GetAddressP2WPKH`, `GetAddressP2WSH`
- `GetAddressP2SH-P2WPKH`, `GetAddressP2SH-P2WSH`, `GetAddressP2TR`, `GetAddressP2TR-SP`
- `Mnemonic2QRCode`, `Mnemonic2CompactQRCode`
- `GetUTXO`, `GetBalance`

これは32種類の別々の暗号不具合ではなく、パイプライン処理に共通する問題です。
単一入力の値が誤っているという意味ではありません。
`i2h`・`i2b`・`GetMnemonic` は入力バイトを集約するAPIなので、上記の入力ごとの変換とは区別してテストしています。
既に修正されている `ValidateMnemonic`・`GetBIP39Seed` の複数入力テストも保持しています。
