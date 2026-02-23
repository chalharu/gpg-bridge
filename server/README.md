# gpg-bridge server

`server/` は gpg-bridge のバックエンド API を提供する Rust バイナリです。

## 役割

- ペアリング、署名要求、イベント配信などの API エンドポイントを提供する
- 永続化データと連携し、クライアントとデーモン間の仲介を行う

## 現在の状態

- HTTP サーバー起動基盤（axum + tokio）を実装済み
- 設定読み込み（環境変数）、tracing 初期化、DB 接続・マイグレーション・ヘルスチェックを実装済み
- `GET /health` の疎通確認エンドポイントを実装済み（Accept バージョニング、RFC9457 Problem Details エラー、CORS・セキュリティヘッダー対応）
