# テスト

最近のバグ再現だけでなく、正常系・境界値・異常系・公開仕様との一致を検証します。
テストはオフラインで動作し、Pester・Python・Goのインストールは不要です。
Python/Goは参照データを再生成するときにだけ使います。

## 実行

リポジトリのルートから、新しいPowerShellセッションで実行します。

```powershell
./tests/Run-Tests.ps1
./tests/Run-Tests.ps1 -IncludeFast
./tests/Run-Tests.ps1 -Suite 'Transactions*'
./tests/Run-Tests.ps1 -PowerShellPath 'C:\Program Files\PowerShell\7\pwsh.exe'
```

通常は実行中のPowerShellと同じ実行ファイルで子プロセスを起動します。
各 `*.Tests.ps1` は別プロセスで実行するため、PowerShellクラス、Add-Type、関数の差し替え、
Fast版のキャッシュが別スイートに持ち越されません。Fast版は明示指定した場合のみ実行し、
ファイルがなければエラーにします。

全結果は `tests/results/<実行ID>/` に保存します。`summary.json` が全体結果、
各スイートのJSONがケース別の名前・成否・所要時間・エラー、`.log` が標準出力・標準エラーです。
このディレクトリだけをGit管理から除外します。

失敗、タイムアウト、読み込みエラー、結果ファイル未生成、空のスイートは終了コード1になります。
失敗したスイートがあっても残りを実行します。既定のタイムアウトはスイートごとに300秒です。
低速環境では `-TimeoutSeconds 600` などで変更できます。

**現在は新規検出した本体の問題により失敗するケースがあります。**
期待値を現状の誤動作に合わせたり、失敗をスキップしたりしていません。
詳細は [KNOWN-FAILURES.md](KNOWN-FAILURES.md) を参照してください。

## 検証範囲

| 分野 | 主な検証内容 | スイート |
|---|---|---|
| バイト・整数・符号化 | 全256バイト、パイプラインの集約、i2hオプション、32/64bit境界、CompactSize、PUSHDATA、ScriptNum、記述子チェックサム | Encoding |
| BIP39・PBKDF2 | 英語24・日本語24の公開ベクトル、エントロピー全5長、チェックサム・未知語・語数、NFKD・空白、TREZORシード・拡張鍵、RFC6070 | Mnemonic |
| BIP32・HDWallet | 公開ベクトル1〜4の全17ノード、ベクトル5の無効鍵16件、公開鍵のみの派生、最大インデックス・深さ、ネットワーク、SLIP形式、キャッシュ・Dispose | HDWallet |
| 稀な派生条件 | HMACを差し替え、IL=0、IL>=n、子鍵0/無限遠点、候補スキップ、末尾インデックス枯渇を検証 | DerivationFaults |
| 楕円曲線・ハッシュ | 点加算・倍算・任意基点・負のスカラー・無限遠点・Jacobian正規化・逆元、独立したハッシュ期待値 | CurveAndHash |
| 鍵・アドレス | 5種類の秘密スカラー×両ネットワーク、圧縮/非圧縮WIF、8種のアドレス・出力スクリプト、BIP350全23アドレス例、BIP86、Taproot tweak、URI | Addresses |
| トランザクション | TXin/TXout/Witness/TX/TXS/DERのバイト列、別パーサーでの読出し、不正構造、MAX_MONEY・dust境界 | Transactions |
| 署名ハッシュ | BIP143公開プリイメージ14件、BIP341公開key-path例、独立生成した68ケース（Segwit全6フラグ、Taproot全7フラグ×入力×annex×拡張） | Transactions |
| 署名 | 独立RFC6979/ECDSA期待値、乱数ECDSA・Schnorr署名を別実装で検証、その検証器をBIP340の正常/異常ベクトルで検証 | Signatures |
| メッセージ | 固定署名、空文字・日本語・252/253/65536バイト、改変、両ネットワーク・各アドレス形式、Electrum・独自Taproot拡張 | Signatures |
| 送金生成 | Legacy/P2SH/各Segwit/Taproot key-path/script-path×両ネットワーク、複数入力、選択順、金額、お釣り、メモ、locktime、生成署名の検証、残高不足、dust、誤った鍵、Nulldata、CLTV | Builders |
| 通信境界 | HTTP差し替え、UTXOの確認済みフィルター・順序・スクリプト、ネットワーク別URL、空/単一応答、再試行・打ち切り、残高サービスのフォールバック | Network |
| パイプライン | 入力を複数渡したとき、各公開関数が件数・順序を保持するか。単一呼出しとの比較 | Pipeline / Network |
| SeedQR | 英語・日本語の全48ベクトルから通常/Compactペイロードを検証、エントロピー・チェックサム・ECC指定、無効ニーモニック | SeedQR |
| aezeed | 既存のLND/btcd参照データ、パスフレーズ・認証・Unicode・バージョン・破損・BIP39との取り違え | Aezeed |
| 使用例 | 08以外の全例（01〜07・09・99）の記録済み出力を空白・空行・最終改行まで照合。99は参照行・IL定数・復元鍵も検査 | Examples |
| テスト基盤 | アサーションの失敗判定、フィクスチャのSHA256・公式ベクトル件数 | Harness |

既存の回帰テストは機能別スイートへ統合し、すべて `Test` と共通の `Assert-*` を使います。
`CompactSize` は `Encoding`、`DerivationNetwork`・`ExtendedKeyRoundtrip`・再インポート時のキャッシュ検査は
`HDWallet`、`ZeroIL` は `DerivationFaults`、ニーモニックの複数入力は `Pipeline` に移しました。
初期化前の公開鍵インポートはBIP32公開ベクトルのインポート検査と重複するため一本化しました。
aezeedのBIP39検査は同じセッションでの共存を検証するため残しています。

### 例の出力スナップショット

`Examples.Tests.ps1` は08以外の `examples/*.ps1` を自動検出します。
標準出力と `Write-Host` の出力を合わせ、改行コードをLFへ揃えて `.out` と厳密に比較します。
スペース・タブ・空行・最終改行は除去しません。`.out` はUTF-8（BOMなし）・LFで保存します。
99はウォレットの一時コピーに条件付き `Write-Host $il` を挿入して実行します。
コメントの参照行が通常版の `HDWallet.Derive()` 内の指定コードであること、
`$i`・`$ii` の定数と出力順の説明が実際の5番目・4番目の値に一致すること、復元鍵も検査します。
通常版・Fast版とも一時コピーを使い、元の本体は変更しません。

出力変更を意図した場合だけ、次を実行して差分をレビューしてください。テストやCIは自動更新しません。

```powershell
./tests/Update-ExampleSnapshots.ps1
```

## 期待値と独立性

- `fixtures/manifest.json` に出典URL、取得日、元データ/保存データのSHA256、抽出範囲を記録しています。
- 公式データはローカルに同梱し、毎回ネットワークから取得しません。
- `reference/generate-core-vectors.py` はPowerShell本体を呼ばず、Python標準ライブラリと独立したaffine座標演算で期待値を生成します。
- `ReferenceCrypto.cs` はテスト専用の独立した署名検証器です。製品用暗号ライブラリとして使用しないでください。
- `TransactionSupport.ps1` はバイト列を別途解析します。送金生成の署名検証では本体の署名ハッシュ作成器も使用しますが、その作成器自体を別の公式/独立ベクトルで検証しています。
- `examples/*.out` は既存動作の回帰用記録で、仕様準拠の根拠とは区別します。`02_seed2addresses.out` 末尾の、スクリプトに出力処理が存在しない単独の `P` は記録ミスとして除去しました。

公式ベクトルを更新する場合は出典からファイルを取得し、
`python3 tests/reference/import-official-vectors.py <取得先ディレクトリ>` を実行します。
独立生成データは `python3 tests/reference/generate-core-vectors.py` で再生成できます。
その際、manifestの対応するSHA256もレビューの上で更新してください。
実装本体の出力をコピーして正解データを更新しないでください。

## 自動テストの限界

全入力・全分岐の完全性や、暗号実装の安全性を証明するものではありません。
行/分岐カバレッジの割合は測定していません。
以下は別途確認が必要です。

- 実サービスの稼働・応答仕様変更、実ノードの受理/ブロードキャスト、実SATSCARD。
- QR画像の実際の描画・読み取り、Windows Formsの画面操作。
- 任意のカスタムスクリプトの実行可能性。生成APIは単一署名で充足できるスクリプトに限定され、汎用Scriptインタープリターではありません。
- 乱数源の品質、タイミング攻撃、メモリーからの秘密消去、性能上限。
- examples/08は実SATSCARDが必要なため、出力照合の対象外です。

CIはWindows PowerShell 5.1、Windows PowerShell 7、Linux PowerShell 7を設定しています。
ローカルで実行できた環境と実測値は [VALIDATION.md](VALIDATION.md) に記録します。
