# Google Cloud KMS × クライアントサイド・エンベロープ暗号化における Tink の役割

> 対象読者：Cloud KMS を使ってアプリ側でデータを暗号化したいが、Tink を採用するかどうか決めかねている開発者・アーキテクト
> 結論を先に：**Tink は必須ではない。** ただし「自前で実装した場合に自分たちが背負う責任」の多くを Tink が肩代わりしてくれるため、特別な理由がなければ Tink を使うほうが安全かつ低コスト。

---

## 1. 前提：エンベロープ暗号化とは

エンベロープ暗号化では、2種類の鍵を使い分けます。

| 鍵 | 役割 | どこにあるか |
|---|---|---|
| **DEK**（Data Encryption Key） | 実際のデータを暗号化する鍵 | アプリ側（ローカル）で生成・使用 |
| **KEK**（Key Encryption Key） | DEK を暗号化（ラップ）する鍵 | Cloud KMS の中。外に出ることはない |

### 暗号化の流れ
1. アプリが DEK をローカルで生成する
2. DEK でデータをローカル暗号化する
3. Cloud KMS に DEK を送り、KEK で暗号化（ラップ）してもらう
4. 「暗号化データ」と「ラップ済み DEK」をセットで保存する

### 復号の流れ
1. 「暗号化データ」と「ラップ済み DEK」を取り出す
2. Cloud KMS にラップ済み DEK を送り、復号（アンラップ）してもらう
3. 平文の DEK でデータをローカル復号する

### なぜわざわざこうするのか
- Cloud KMS の Encrypt/Decrypt API は入力サイズに上限（64 KiB）があり、大きなデータを直接暗号化できない
- 大量データの暗号化はローカルで高速に行い、KMS には「鍵の鍵」だけを任せることで、性能と鍵管理を両立できる
- KEK は KMS の外に出ないため、ローテーション・無効化・破棄・アクセス監査を一元的に行える

---

## 2. Tink は必須か？ → 必須ではない

Google Cloud の公式ドキュメント（Envelope encryption）自体、DEK によるデータ暗号化の例として **OpenSSL** を挙げており、Tink を使わない手順も前提にしています。

必要なのは以下の部品だけなので、理屈の上では誰でも組み立てられます。

- 暗号論的に安全な乱数生成器（DEK・ノンス生成用）
- AES-256-GCM などの AEAD 実装（言語標準や OpenSSL、`cryptography` など）
- Cloud KMS のクライアントライブラリ（DEK のラップ／アンラップ用）

問題は「組み立てられるか」ではなく、**「正しく組み立て続けられるか」**です。以下、2つのケースで比較します。

---

## 3. ケース A：Tink を使わない場合（自前実装）

### 3.1 自分たちで決めて・実装しなければならないこと

| # | 項目 | 何を判断する必要があるか | 間違えるとどうなるか |
|---|---|---|---|
| 1 | アルゴリズム／モード選択 | AES-GCM？ CBC+HMAC？ 鍵長は？ | 弱いモード（ECB 等）や認証なしモードを選ぶと、盗聴・改ざんに弱くなる |
| 2 | DEK 生成 | 安全な乱数源を使うか | 予測可能な鍵になれば暗号が無意味に |
| 3 | ノンス（IV）管理 | 長さ、生成方法、再利用防止 | GCM でノンスを再利用すると機密性・完全性が根本から崩れる |
| 4 | 関連データ（AAD） | 何を AAD に含めるか（レコード ID 等） | 暗号文を別レコードに付け替える攻撃を防げない |
| 5 | KMS 呼び出し | Encrypt/Decrypt API の呼び出し、リトライ、エラー処理 | 例外処理の漏れで平文 DEK がログに残る等の事故 |
| 6 | **保存フォーマット設計** | ラップ済み DEK・ノンス・暗号文・タグをどう並べるか、長さ情報、バージョン番号 | 後から形式を変えられない。言語やチームごとに微妙に違う形式が乱立する |
| 7 | 復号時のパース | 長さフィールドの検証、異常値の扱い | 不正な入力でクラッシュ・メモリ過剰確保などの脆弱性 |
| 8 | 将来の移行 | アルゴリズム変更時に新旧形式をどう共存させるか | 「バージョン番号を入れておけばよかった」問題 |
| 9 | 言語間互換 | Java で暗号化 → Go で復号、などが必要か | 各言語で同じ形式を再実装し、相互テストを維持する負担 |
| 10 | レビューと保守 | 暗号に詳しい人が実装をレビューできるか | 「動くが安全ではない」コードが本番に残る |

### 3.2 自前実装のイメージ（Python, 概念図）

```python
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from google.cloud import kms

kms_client = kms.KeyManagementServiceClient()
KEY_NAME = "projects/.../locations/.../keyRings/.../cryptoKeys/..."

def encrypt(plaintext: bytes, aad: bytes) -> bytes:
    dek = AESGCM.generate_key(bit_length=256)        # ① DEK 生成
    nonce = os.urandom(12)                            # ② ノンス生成（再利用厳禁）
    ct = AESGCM(dek).encrypt(nonce, plaintext, aad)   # ③ ローカル暗号化
    wrapped = kms_client.encrypt(                     # ④ KMS で DEK をラップ
        request={"name": KEY_NAME, "plaintext": dek}
    ).ciphertext
    # ⑤ 保存フォーマットは自分で設計する必要がある
    return (b"\x01"                                   # 形式バージョン
            + len(wrapped).to_bytes(4, "big")         # ラップ済み DEK 長
            + wrapped + nonce + ct)

def decrypt(blob: bytes, aad: bytes) -> bytes:
    # ⑥ パース処理・長さ検証・バージョン分岐もすべて自前
    ...
```

短く見えますが、**①〜⑥のどれか一つでも誤ると、テストは通るのに安全ではない**状態になります。暗号のバグは機能テストでは見つからないのが厄介な点です。

### 3.3 自前実装が向いているケース
- 既存システムや外部仕様と**バイト単位で互換性を取る必要がある**
- Tink が対応していない言語・環境で動かす必要がある
- 暗号の専門家がチーム内にいて、継続的にレビューできる体制がある

---

## 4. ケース B：Tink を使う場合

### 4.1 Tink がやってくれること

Tink の `KmsEnvelopeAead` を使うと、開発者が渡すのは **KEK の URI と認証情報** だけです。暗号化時、Tink は次をまとめて行います。

1. ランダムな DEK を生成し、データをローカルで暗号化
2. Cloud KMS に DEK のラップを依頼
3. ラップ済み DEK と暗号化データを連結し、**1つの暗号文として返す**

復号時はその逆を自動で行います。つまり、ケース A の表の **#1〜#9 の大部分が Tink 側の責任**になります。

| ケース A の項目 | Tink を使うと |
|---|---|
| アルゴリズム選択 | `AES256_GCM` などの安全なテンプレートから選ぶだけ。危険な選択肢はそもそも存在しない |
| DEK 生成 | Tink が暗号化ごとに新しい DEK を自動生成 |
| ノンス管理 | 利用者はノンスを触れない（渡す API がない） |
| 保存フォーマット | Tink が定義済み。自前設計は不要 |
| 復号時のパース | Tink が実装・テスト済み |
| 言語間互換 | Java / Python / Go / C++ で同じ形式を扱える |
| レビュー | Google の暗号専門家が設計・レビューし、多数の本番システムで使われている |

### 4.2 Tink を使った実装イメージ（Python）

```python
import tink
from tink import aead
from tink.integration import gcpkms

aead.register()

KEK_URI = "gcp-kms://projects/PROJECT_ID/locations/LOCATION/keyRings/KEY_RING/cryptoKeys/KEY_NAME"

client = gcpkms.GcpKmsClient(KEK_URI, credentials_path)
remote_aead = client.get_aead(KEK_URI)
env_aead = aead.KmsEnvelopeAead(aead.aead_key_templates.AES256_GCM, remote_aead)

ciphertext = env_aead.encrypt(plaintext, associated_data)
plaintext  = env_aead.decrypt(ciphertext, associated_data)
```

開発者が意識するのは「何を暗号化するか」と「AAD に何を入れるか」だけになります。

### 4.3 Tink の 2 つの使い方

Tink の公式ドキュメントでは、クラウド KMS とのクライアントサイド暗号化に 2 つの方式を挙げています。

| 方式 | 仕組み | 向いている場面 |
|---|---|---|
| **KMS Envelope AEAD**（`KmsEnvelopeAead`） | 暗号化ごとに新しい DEK を作り、KMS でラップして暗号文に埋め込む | シンプルさ重視。DEK を一切管理したくない |
| **キーセットを KMS で暗号化して保存** | Tink のキーセット（DEK 群）を KMS の KEK で暗号化して保存し、起動時に一度だけ復号して使う | KMS への呼び出し回数を減らしたい／AEAD 以外（署名・MAC・決定論的暗号化など）も使いたい |

`KmsEnvelopeAead` は**暗号化・復号のたびに KMS への RPC が発生**します。大量の小さなレコードを高頻度に処理する場合は、レイテンシ・コスト・KMS のクォータを考えて後者を検討してください。

---

## 5. 比較まとめ

| 観点 | ケース A：Tink なし | ケース B：Tink あり |
|---|---|---|
| 必須か | — | 必須ではない |
| 実装量 | 多い（暗号処理＋フォーマット＋パース） | 少ない（数行） |
| 誤用リスク | 高い（ノンス再利用、モード選択ミス等） | 低い（危険な操作が API から排除） |
| 暗号文フォーマット | 自前設計・自前保守 | Tink 定義済み |
| 多言語互換 | 各言語で再実装・相互テストが必要 | 主要言語で共通 |
| レビュー負担 | 暗号の専門知識が必要 | Tink 側でレビュー済み |
| 柔軟性 | 最大（何でもできる） | 意図的に制限されている |
| 既存形式との互換 | 合わせられる | Tink 形式に縛られる |
| ベンダー依存 | 低い | Tink 形式への依存が生じる（OSS なので実質的なリスクは小さい） |

---

## 6. Tink を使っても「残る」責任

Tink は暗号処理の正しさを保証しますが、以下は引き続き利用者の責任です。

- **IAM 設計**：誰（どのサービスアカウント）が KEK で Encrypt/Decrypt できるか。最小権限で付与する
- **KEK のローテーション方針**：Cloud KMS で KEK を自動ローテーションした場合、新しいデータは新しいバージョンでラップされる。古いデータを復号するには古い鍵バージョンを有効のまま残す必要がある。必要に応じて古いデータの再暗号化も計画する
- **AAD の設計**：レコード ID やテナント ID などを AAD に含め、暗号文の付け替えを防ぐ
- **平文の扱い**：復号後の平文をログや例外メッセージに出さない
- **可用性**：KMS に到達できないと復号できない。リトライ、タイムアウト、障害時の挙動を設計する
- **監査**：Cloud Audit Logs で KMS の利用状況を確認する

---

## 7. 判断の目安

**Tink を使うべきケース（ほとんどの新規開発）**
- 新規にクライアントサイド暗号化を導入する
- チームに暗号の専門家がいない、または常駐していない
- 複数言語・複数サービスで同じ暗号データを扱う
- 将来のアルゴリズム移行や鍵ローテーションを見越しておきたい

**Tink を使わない選択肢を検討するケース**
- 既存の暗号文フォーマットや外部システムの仕様に厳密に合わせる必要がある
- Tink が対応していない言語・実行環境で動かす必要がある
- 監査・規制の都合で、特定の暗号ライブラリ（FIPS 認定モジュール等）の直接利用が求められる
  （この場合も、Tink が該当ライブラリ上で動作する構成が取れないかをまず確認する価値がある）

> **一言でいえば**：エンベロープ暗号化は「理屈は簡単、実装の細部が危険」な仕組みです。Tink は、その危険な細部を Google の暗号専門家が作り込んだ部品に置き換えてくれます。Tink を使わない場合、同じ品質を自分たちで実現し、保守し続ける責任を負うことになります。

---

## Sources（原文の抜粋つき）

- [Client-side encryption with Tink and Cloud KMS | Google Cloud](https://docs.cloud.google.com/kms/docs/client-side-encryption)
  原文：*"You don't need to implement this envelope encryption process from scratch when you use Tink."*
  → Tink を使えば、エンベロープ暗号化の処理を一から実装する必要はない。

- [Envelope encryption | Google Cloud](https://docs.cloud.google.com/kms/docs/envelope-encryption)
  原文：*"The KEK never leaves Cloud KMS."*
  → KEK は Cloud KMS の外に出ない。DEK によるデータ暗号化の例として OpenSSL も紹介されており、Tink は必須ではない。

- [I want to use client-side encryption with a cloud KMS | Tink](https://developers.google.com/tink/client-side-encryption)
  原文：*"so you don't need to handle the DEK yourself"*
  → `KmsEnvelopeAead` は暗号化ごとに DEK を生成・ラップし、暗号文に含めるため、DEK を自分で扱う必要がない。暗号化・復号のたびに KMS への RPC が発生する点も明記されている。

- [About client-side encryption | Cloud SQL for MySQL](https://docs.cloud.google.com/sql/docs/mysql/client-side-encryption)
  原文：*"Instead of implementing envelope encryption from scratch, in this document we use Tink."*
  → Cloud SQL の列単位暗号化の例でも、エンベロープ暗号化を一から実装する代わりに Tink を使っている。
