# gpg-bridge mobile

`mobile/` は gpg-bridge のモバイルクライアント（Flutter）です。

## 目的

- サーバーからの要求通知を受け取り、ユーザー操作を受け付けるUIを提供する
- 今後の Android Keystore 連携（ネイティブブリッジ）を実装する土台とする

## 現在の状態

- Flutter の初期スキャフォールドを作成済み
- `flutter analyze` 通過

## 開発コマンド

```bash
flutter pub get
flutter analyze
flutter run
```

## 補足

- 秘密鍵操作は Flutter 層に直接持たせず、Android/iOS ネイティブ層を経由する設計を前提とする
