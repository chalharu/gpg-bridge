---
created: 2026-03-09
updated: 2026-03-09
---
# Mobile Screen Design

現在の Flutter 実装に存在する主要画面を、設計レビュー向けに簡潔に整理した文書です。対象は `mobile/lib/main.dart`、`mobile/lib/router`、`mobile/lib/pages` 配下の実装済み画面です。

## Visual Overview

<svg viewBox="0 0 1040 740" width="100%" role="img" aria-label="Mobile app screen overview">
  <style>
    .bg { fill: #f8fafc; }
    .shell { fill: #e0f2fe; stroke: #0369a1; stroke-width: 2; }
    .screen { fill: #ffffff; stroke: #334155; stroke-width: 1.5; }
    .modal { fill: #fef3c7; stroke: #b45309; stroke-width: 1.5; }
    .accent { fill: #dcfce7; stroke: #166534; stroke-width: 1.5; }
    .arrow { stroke: #475569; stroke-width: 2; fill: none; marker-end: url(#arrow); }
    .label { font: 15px sans-serif; fill: #0f172a; font-weight: 600; }
    .small { font: 12px sans-serif; fill: #334155; }
  </style>
  <defs>
    <marker id="arrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto">
      <path d="M0,0 L0,6 L9,3 z" fill="#475569" />
    </marker>
  </defs>
  <rect class="bg" x="0" y="0" width="1040" height="740" rx="24" />

  <rect class="accent" x="70" y="70" width="220" height="92" rx="16" />
  <text class="label" x="100" y="105">Register</text>
  <text class="small" x="100" y="130">/register</text>
  <text class="small" x="100" y="148">初回端末登録</text>

  <rect class="shell" x="385" y="52" width="560" height="560" rx="24" />
  <text class="label" x="410" y="86">MainShell</text>
  <text class="small" x="410" y="108">下部ナビゲーション: Home / Keys / Pairing / Settings</text>

  <rect class="screen" x="420" y="135" width="220" height="110" rx="14" />
  <text class="label" x="448" y="170">Home</text>
  <text class="small" x="448" y="194">/</text>
  <text class="small" x="448" y="214">登録解除導線</text>

  <rect class="screen" x="690" y="135" width="220" height="150" rx="14" />
  <text class="label" x="718" y="170">Keys</text>
  <text class="small" x="718" y="194">/keys</text>
  <text class="small" x="718" y="214">E2E 公開鍵タブ</text>
  <text class="small" x="718" y="232">GPG 鍵タブ</text>
  <text class="small" x="718" y="250">GPG 鍵インポート画面へ遷移</text>

  <rect class="screen" x="420" y="325" width="220" height="125" rx="14" />
  <text class="label" x="448" y="360">Pairing</text>
  <text class="small" x="448" y="384">/pairing</text>
  <text class="small" x="448" y="404">一覧 / 削除 / QR スキャン起点</text>

  <rect class="screen" x="690" y="325" width="220" height="110" rx="14" />
  <text class="label" x="718" y="360">Settings</text>
  <text class="small" x="718" y="384">/settings</text>
  <text class="small" x="718" y="404">テーマ切替</text>

  <rect class="modal" x="720" y="482" width="190" height="92" rx="14" />
  <text class="label" x="742" y="517">GPG Key Import</text>
  <text class="small" x="742" y="541">Navigator.push</text>
  <text class="small" x="742" y="559">貼り付け解析と取込</text>

  <rect class="modal" x="115" y="286" width="220" height="104" rx="14" />
  <text class="label" x="145" y="321">QR Scan</text>
  <text class="small" x="145" y="345">/pairing/scan</text>
  <text class="small" x="145" y="363">JWT QR を読み取りペアリング</text>

  <rect class="modal" x="70" y="505" width="265" height="116" rx="14" />
  <text class="label" x="100" y="540">Sign Request</text>
  <text class="small" x="100" y="564">/sign-request/:requestId</text>
  <text class="small" x="100" y="582">FCM 受信で push 表示</text>
  <text class="small" x="100" y="600">承認 / 拒否 / 無視 / 期限切れ</text>

  <path class="arrow" d="M290 116 L385 116" />
  <path class="arrow" d="M530 245 L530 325" />
  <path class="arrow" d="M800 285 L800 482" />
  <path class="arrow" d="M420 385 L335 338" />
  <path class="arrow" d="M205 390 L205 505" />
  <path class="arrow" d="M182 162 L182 286" />
  <text class="small" x="305" y="106">登録完了</text>
  <text class="small" x="826" y="468">GPG タブから遷移</text>
  <text class="small" x="236" y="432">FCM / 直前画面へ戻る</text>
</svg>

## Navigation Structure

| Screen | Route / Presentation | Entry point |
| --- | --- | --- |
| Register | `/register` | 未登録時の初期到達先 |
| Home | `/` | 登録済み MainShell のタブ |
| Keys | `/keys` | 登録済み MainShell のタブ |
| Pairing | `/pairing` | 登録済み MainShell のタブ |
| QR Scan | `/pairing/scan` | Pairing の FAB |
| Settings | `/settings` | 登録済み MainShell のタブ |
| Sign Request | `/sign-request/:requestId` | FCM 受信時に push |
| GPG Key Import | ルート未定義、`Navigator.push` | Keys の GPG 鍵タブ FAB |

## Screen Notes

### 1. Register

- Purpose: 端末未登録状態でデバイス登録を完了する。
- Key UI elements: AppBar「Register」、中央の登録ボタン、処理中インジケータ。
- Primary actions: Complete registration 実行。
- State / notes: 成功後に token refresh listener を開始。失敗時は SnackBar 表示。未登録時は他ルートへ進めない。

### 2. MainShell

- Purpose: 登録後の主要 4 画面を下部ナビゲーションで切り替える。
- Key UI elements: NavigationBar、4 destinations（ホーム / 鍵管理 / ペアリング / 設定）。
- Primary actions: タブ切替、同一タブ再選択時はその branch の初期位置へ戻る。
- State / notes: `StatefulShellRoute.indexedStack` により各 branch の状態を保持する構成。

### 3. Home

- Purpose: 登録済み端末のホーム。現状は登録解除の起点。
- Key UI elements: AppBar「ホーム」、中央の Reset registration ボタン、処理中インジケータ。
- Primary actions: 登録解除。
- State / notes: 初回表示後に device JWT 更新確認、FCM token 更新確認、token refresh listener 開始。解除失敗は SnackBar 表示。

### 4. Keys

- Purpose: E2E 公開鍵と GPG 鍵の管理を 1 画面で扱う。
- Key UI elements: AppBar「鍵管理」、TabBar、TabBarView。
- Primary actions: タブ切替。
- State / notes: 画面自体はコンテナで、実操作は各タブ側にある。

### 5. E2E Keys Tab

- Purpose: サーバーに登録済みの E2E 公開鍵一覧確認と追加・削除。
- Key UI elements: ローディング表示、エラー表示と再試行、空状態メッセージ、鍵カード一覧、デフォルト鍵の star アイコン、追加 FAB。
- Primary actions: 一覧再読込、鍵ペア生成、鍵削除。
- State / notes: pull-to-refresh 対応。削除前に確認ダイアログ表示。`use` に応じて「認証用 / 暗号化用」を表示。

### 6. GPG Keys Tab

- Purpose: GPG 鍵一覧の確認、削除、インポート画面への遷移。
- Key UI elements: ローディング表示、エラー表示と再試行、空状態メッセージ、鍵カード一覧、インポート FAB。
- Primary actions: 一覧再読込、鍵削除、GPG 鍵インポート画面を開く。
- State / notes: pull-to-refresh 対応。削除前に確認ダイアログ表示。Keygrip は短縮表示。

### 7. GPG Key Import

- Purpose: アーマード鍵テキストを解析し、選択した鍵を端末保管とサーバー登録へ取り込む。
- Key UI elements: AppBar「GPG鍵インポート」、複数行 TextField、解析ボタン、解析エラー表示、検出鍵のチェックリスト、インポートボタン。
- Primary actions: 鍵文字列の解析、検出鍵の選択、インポート実行。
- State / notes: 鍵未入力・解析失敗・インポート失敗を明示。秘密鍵素材の保存後に API 登録し、API 失敗時はベストエフォートでロールバック。

### 8. Pairing

- Purpose: ペアリング済みデバイス一覧の確認と解除、QR スキャンへの導線提供。
- Key UI elements: AppBar「ペアリング」、ローディング表示、エラー表示と再試行、空状態メッセージ、一覧タイル、削除アイコン、QR スキャン FAB。
- Primary actions: 一覧再読込、ペアリング解除、QR スキャン画面へ遷移。
- State / notes: 各タイルで解除中スピナーを表示。解除前に確認ダイアログ表示。日時は `YYYY/MM/DD HH:mm` 形式。

### 9. QR Scan

- Purpose: QR コードから pairing JWT を読み取り、ペアリングを完了する。
- Key UI elements: AppBar「QRコードスキャン」、カメラスキャンビュー、処理中インジケータ。
- Primary actions: QR 検出、JWT 形式検証、ペアリング実行。
- State / notes: JWT 形式でない場合は即座に SnackBar。成功時は成功通知後に前画面へ戻る。失敗時はエラー通知後に再スキャン可能。

### 10. Settings

- Purpose: アプリテーマを切り替える。
- Key UI elements: AppBar「設定」、テーマ見出し、3 つの RadioListTile。
- Primary actions: システム設定 / ライト / ダークの選択。
- State / notes: 永続化は `themeModeStateProvider` 経由。現時点の設定 UI はテーマ切替のみ。

### 11. Sign Request

- Purpose: 署名要求の内容確認と承認判断。
- Key UI elements: AppBar「署名要求」、残り時間バナー、署名詳細カード、承認 / 拒否 / 無視ボタン。
- Primary actions: 承認、拒否、無視。
- State / notes: FCM 受信時に push 表示される一時画面。読み込み中、エラー、要求未発見に対応。残り 60 秒未満でバナーが警告色になり、期限切れ時は SnackBar を出して自動で閉じる。

## Review Notes

- 現在の画面導線は「未登録フロー」「MainShell 配下の 4 タブ」「一時的に開く補助画面」に大別できる。
- 鍵管理は 1 route 内に 2 タブと 1 サブ画面を持つため、レビュー時は `Keys` を単一画面ではなく画面群として扱うほうが分かりやすい。
- 確認ダイアログや SnackBar は複数画面で使われるが、本書では独立 screen ではなく各画面の state/notes に含めた。
