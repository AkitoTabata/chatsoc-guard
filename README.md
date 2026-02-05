# ChatSOC-Guard

ChatSOC-Guard は、簡易チャットサービスを題材に、  
**荒らし行為の検知・制御・監視までを一貫して実装した、SOC視点のWebセキュリティ検証プロジェクト**です。

- Web 側：匿名チャット + 投稿制御
- Runner 側：ログ監視 + リスク検知 + Discord 通知

## ドキュメント
- [Design Notes / 開発メモ](./DESIGN_NOTES.md)

## 背景・動機

私は過去にオープンチャットサイトで、  
連続投稿制限を回避しているユーザーや、BANされてもすぐ戻ってくるユーザー、  
セッションやトークンの話をしている荒らしを何度も目にしました。

当時は「すごい」「怖い」という感覚でしたが、  
セキュリティに興味を持つようになってから、  
「なぜそれが可能だったのか」「運営側はどうすれば防げたのか」を  
自分の手で再現・理解したいと考えるようになりました。

## プロジェクトの目的

本プロジェクトでは、まずチャットサービスを自作し、  
それを攻撃対象と見立ててレート制限・一時BAN機構を実装。  
さらに、セキュリティイベントを構造化ログとして出力し、  
監視プロセスが不正挙動を検知して外部通知する簡易SOC基盤を構築しています。

単なるWebアプリ開発ではなく、  
**「検知できるか」「説明できるか」「運用できるか」**を重視した構成を意識しています。

## 想定脅威（Threat Model）

本プロジェクトでは、以下のような脅威を想定しています。

- **XSS**：チャット投稿内容を通じたスクリプト注入
- **CSRF**：第三者サイトからの不正な投稿
- **スパム・連続投稿**：サービス妨害やログ汚染
- **通知チャネルの悪用**：Discord通知へのメンション荒らし
- **秘密情報の漏洩**：Webhook URL や管理用トークンの流出
- **運用事故**：起動方法や実行ディレクトリ依存による設定ミス

## 実装済みセキュリティ要素

- Redisを用いたレート制限・一時BAN  
- 匿名ID（Cookie）によるオープンチャット識別  
- セキュリティイベントの構造化ログ出力  
- CSRF対策（Cookie + ヘッダトークン照合)
- SOC runner によるリアルタイム監視  
- Discord Webhook 通知  
- ユーザーメンションによるDiscordの通知荒らしを防止
- BAN回避行動の相関検知  
- fingerprint単位の危険度スコアリング  
- 危険度に応じた自動ブロック（エスカレーション制御）  
- Redis障害時のエラーハンドリング（500ではなく503で返す）

検知イベント例：
- `security.rate_limit_hit`
- `security.user_blocked`
- `security.blocked_action_attempt`
- `security.evasion_suspected`
- `security.risk_escalated`
- `security.high_risk_block`
- `system.redis_unavailable`

## 起動方法

### 0. 前提
以下がインストールされていることを確認してください。
- Windows
- Python 3.x
- Docker Desktop

プロジェクト直下に移動：

```powershell
cd chatsoc-guard
```

---

### 1. 環境変数の設定

秘密情報は.envファイルで管理します。
まず、雛形から.envファイルを作成してください。

```powershell
copy .env.example .env
```

.env に以下を設定します。

`DISCORD_WEBHOOK_URL`

Discord の Webhook URL（SOC 通知用）

`DEBUG_ADMIN_TOKEN`

管理用デバッグトークン（ローカル用）

`DEBUG_MODE`

`0`：debug API 無効（通常はこちら）

`1`：debug API 有効（ローカル検証用）

`COOKIE_SECURE`

`0`：HTTP想定（ローカル）

`1`：HTTPS想定（将来用）

※ .env は Git 管理対象外です。

---

### 2. Webサーバ起動（FastAPI + Redis）

Webサーバ起動：

```powershell
.\scripts\start.ps1
```

ブラウザでアクセス：  
http://127.0.0.1:8000/chat  

※このターミナルは Webサーバ用（閉じない）

---

### 3. SOC runner 起動（別ターミナル）

新しいPowerShellを開いて同じプロジェクト直下へ移動：

```powershell
cd chatsoc-guard
```

runner起動：

```powershell
.\scripts\start-runner.ps1
```

または：

```powershell
.\.venv\Scripts\python.exe .\detection\runner.py
```

以下が表示されればOK：

```powershell
[INFO] runner started. watching: logs/app.jsonl
```

※このターミナルは SOC runner 用

---

### 停止方法

Webサーバ / runner 停止：

```
Ctrl + C  
```

Redis 停止：

```powershell
docker compose down
```

---

### 動作確認

- http://127.0.0.1:8000/chat が開く  
- 連続投稿で制限がかかる・一時ブロックが発生する
- runner に security イベントが表示される  
- Discord に通知が届く  

## 補足

- 本プロジェクトは学習・ポートフォリオ用途のローカルデモです
- 本番運用を想定する場合は HTTPS、有効期限管理、権限分離等が必要です

## 現時点での課題

開発を進める中で、以下の課題を認識しています。

- 認証・認可機構が未実装
- 本番環境を想定した HTTPS / Secure Cookie 未対応
- ログ保存・ローテーション戦略が未整理
- SOC runner の耐障害性（再起動・通知失敗時の挙動）
- セキュリティイベントの分類・優先度付けが簡易的

## 今後の改善予定

今後、以下のような改善・拡張を検討しています。

- Cookie 属性（Secure / SameSite）の環境別切替の整理
- CSP（Content Security Policy）の強化（unsafe-inline削減など）
- SOC runner のエラーハンドリング強化（バックオフ・再試行制御）
- セキュリティイベントのルール定義・リスクスコア設計の見直し
- 管理者向けダッシュボードの追加（ローカル限定）
- ログのマスキング・構造化の強化

## 開発方針

本プロジェクトでは、以下を重視して開発しています。

- **「なぜ危険か」「なぜこの対策が必要か」を説明できること**
- 完璧な実装よりも、脅威モデルと対策設計の妥当性
- 実運用を意識した事故防止（秘密情報管理・通知暴発防止）

製作途中ではありますが、  
設計意図や課題認識も含めて評価していただける構成を目指しています。