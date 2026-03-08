---
created: 2026-03-09
updated: 2026-03-09
---
# Mobile Screen Design

現在の Flutter 実装に存在する主要画面を、設計レビュー向けに簡潔に整理した文書です。対象は `mobile/lib/main.dart`、`mobile/lib/router`、`mobile/lib/pages` 配下の実装済み画面です。

## Visual Overview

以下は、現在の Flutter 実装に合わせた HTML ベースの画面モックです。Markdown ビューアで SVG が無効でも見えるよう、単純な table / div / inline style のみで構成しています。

<table>
  <tr>
    <td style="vertical-align:top;">
      <div style="width:220px; border:1px solid #475569; border-radius:24px; padding:10px; background:#f8fafc; color:#0f172a;">
        <div style="font-size:11px; text-align:center; padding-bottom:8px; color:#475569;">Register /register</div>
        <div style="border:1px solid #cbd5e1; border-radius:16px; background:#ffffff; overflow:hidden; min-height:390px;">
          <div style="padding:12px 14px; background:#e2e8f0; font-weight:700;">Register</div>
          <div style="padding:24px 16px; text-align:center;">
            <div style="margin:56px 0 18px 0; font-size:13px; color:#334155;">未登録端末の初期到達先</div>
            <div style="display:inline-block; padding:12px 18px; border-radius:999px; background:#2563eb; color:#ffffff; font-weight:700;">Complete registration</div>
            <div style="margin-top:18px; padding:10px; border:1px dashed #94a3b8; border-radius:12px; font-size:12px; color:#475569;">成功後に token refresh listener 開始</div>
          </div>
        </div>
      </div>
    </td>
    <td style="vertical-align:top;">
      <div style="width:220px; border:1px solid #475569; border-radius:24px; padding:10px; background:#eff6ff; color:#0f172a;">
        <div style="font-size:11px; text-align:center; padding-bottom:8px; color:#475569;">MainShell / Home</div>
        <div style="border:1px solid #cbd5e1; border-radius:16px; background:#ffffff; overflow:hidden; min-height:390px;">
          <div style="padding:12px 14px; background:#e2e8f0; font-weight:700;">ホーム</div>
          <div style="padding:16px; text-align:center; min-height:292px;">
            <div style="margin:44px 0 16px 0; padding:12px; border:1px solid #cbd5e1; border-radius:12px; background:#f8fafc; font-size:12px; color:#334155;">初回表示時に JWT / FCM token 更新確認</div>
            <div style="display:inline-block; padding:12px 20px; border-radius:999px; background:#dc2626; color:#ffffff; font-weight:700;">Reset registration</div>
          </div>
          <table style="width:100%; border-top:1px solid #cbd5e1; border-collapse:collapse; font-size:11px; text-align:center;">
            <tr>
              <td style="padding:10px 4px; background:#dbeafe; font-weight:700;">Home</td>
              <td style="padding:10px 4px;">Keys</td>
              <td style="padding:10px 4px;">Pairing</td>
              <td style="padding:10px 4px;">Settings</td>
            </tr>
          </table>
        </div>
      </div>
    </td>
    <td style="vertical-align:top;">
      <div style="width:220px; border:1px solid #475569; border-radius:24px; padding:10px; background:#eff6ff; color:#0f172a;">
        <div style="font-size:11px; text-align:center; padding-bottom:8px; color:#475569;">Keys /keys</div>
        <div style="border:1px solid #cbd5e1; border-radius:16px; background:#ffffff; overflow:hidden; min-height:390px;">
          <div style="padding:12px 14px; background:#e2e8f0; font-weight:700;">鍵管理</div>
          <table style="width:100%; border-bottom:1px solid #cbd5e1; border-collapse:collapse; font-size:12px; text-align:center;">
            <tr>
              <td style="padding:10px 4px; background:#dbeafe; font-weight:700;">E2E公開鍵</td>
              <td style="padding:10px 4px;">GPG鍵</td>
            </tr>
          </table>
          <div style="padding:12px; min-height:260px; position:relative;">
            <div style="padding:10px 12px; margin-bottom:10px; border:1px solid #cbd5e1; border-radius:12px; background:#f8fafc; font-size:12px;">★ 認証用 ES256<br />kid: abcd1234…</div>
            <div style="padding:10px 12px; border:1px solid #cbd5e1; border-radius:12px; background:#f8fafc; font-size:12px;">鍵カード一覧 / pull-to-refresh / 削除</div>
            <div style="position:absolute; right:14px; bottom:14px; width:44px; height:44px; line-height:44px; border-radius:50%; background:#2563eb; color:#ffffff; text-align:center; font-size:28px; font-weight:700;">+</div>
          </div>
          <table style="width:100%; border-top:1px solid #cbd5e1; border-collapse:collapse; font-size:11px; text-align:center;">
            <tr>
              <td style="padding:10px 4px;">Home</td>
              <td style="padding:10px 4px; background:#dbeafe; font-weight:700;">Keys</td>
              <td style="padding:10px 4px;">Pairing</td>
              <td style="padding:10px 4px;">Settings</td>
            </tr>
          </table>
        </div>
      </div>
    </td>
  </tr>
</table>

<p><strong>Flow:</strong> Register 完了後に MainShell へ遷移し、Home / Keys / Pairing / Settings を下部ナビゲーションで切り替える。</p>

<table>
  <tr>
    <td style="vertical-align:top;">
      <div style="width:220px; border:1px solid #475569; border-radius:24px; padding:10px; background:#eff6ff; color:#0f172a;">
        <div style="font-size:11px; text-align:center; padding-bottom:8px; color:#475569;">Pairing /pairing</div>
        <div style="border:1px solid #cbd5e1; border-radius:16px; background:#ffffff; overflow:hidden; min-height:390px;">
          <div style="padding:12px 14px; background:#e2e8f0; font-weight:700;">ペアリング</div>
          <div style="padding:12px; min-height:304px; position:relative;">
            <div style="padding:10px 12px; margin-bottom:10px; border:1px solid #cbd5e1; border-radius:12px; background:#f8fafc; font-size:12px;">client-a<br />ID: pair-001<br />ペアリング日時: 2026/03/09 10:30</div>
            <div style="padding:10px 12px; border:1px solid #cbd5e1; border-radius:12px; background:#f8fafc; font-size:12px;">各行で解除確認ダイアログと削除実行</div>
            <div style="position:absolute; right:14px; bottom:14px; width:48px; height:48px; line-height:48px; border-radius:50%; background:#2563eb; color:#ffffff; text-align:center; font-size:20px; font-weight:700;">QR</div>
          </div>
          <table style="width:100%; border-top:1px solid #cbd5e1; border-collapse:collapse; font-size:11px; text-align:center;">
            <tr>
              <td style="padding:10px 4px;">Home</td>
              <td style="padding:10px 4px;">Keys</td>
              <td style="padding:10px 4px; background:#dbeafe; font-weight:700;">Pairing</td>
              <td style="padding:10px 4px;">Settings</td>
            </tr>
          </table>
        </div>
      </div>
    </td>
    <td style="vertical-align:top;">
      <div style="width:220px; border:1px solid #475569; border-radius:24px; padding:10px; background:#fff7ed; color:#0f172a;">
        <div style="font-size:11px; text-align:center; padding-bottom:8px; color:#475569;">QR Scan /pairing/scan</div>
        <div style="border:1px solid #cbd5e1; border-radius:16px; background:#ffffff; overflow:hidden; min-height:390px;">
          <div style="padding:12px 14px; background:#e2e8f0; font-weight:700;">QRコードスキャン</div>
          <div style="padding:14px; text-align:center;">
            <div style="margin:12px auto 18px auto; width:158px; height:158px; border:2px solid #0f172a; border-radius:16px; background:#f8fafc; line-height:158px; font-size:12px; color:#475569;">camera scan area</div>
            <div style="padding:10px 12px; border:1px dashed #94a3b8; border-radius:12px; font-size:12px; color:#334155;">JWT 形式を検証し、成功で前画面へ戻る</div>
            <div style="margin-top:12px; font-size:12px; color:#475569;">無効な値は SnackBar 表示</div>
          </div>
        </div>
      </div>
    </td>
    <td style="vertical-align:top;">
      <div style="width:220px; border:1px solid #475569; border-radius:24px; padding:10px; background:#eff6ff; color:#0f172a;">
        <div style="font-size:11px; text-align:center; padding-bottom:8px; color:#475569;">Settings /settings</div>
        <div style="border:1px solid #cbd5e1; border-radius:16px; background:#ffffff; overflow:hidden; min-height:390px;">
          <div style="padding:12px 14px; background:#e2e8f0; font-weight:700;">設定</div>
          <div style="padding:16px; min-height:292px;">
            <div style="font-size:13px; font-weight:700; margin-bottom:10px;">テーマ</div>
            <div style="padding:10px 12px; margin-bottom:10px; border:1px solid #cbd5e1; border-radius:12px; background:#f8fafc; font-size:12px;">◉ システム設定に従う</div>
            <div style="padding:10px 12px; margin-bottom:10px; border:1px solid #cbd5e1; border-radius:12px; font-size:12px;">○ ライト</div>
            <div style="padding:10px 12px; border:1px solid #cbd5e1; border-radius:12px; font-size:12px;">○ ダーク</div>
          </div>
          <table style="width:100%; border-top:1px solid #cbd5e1; border-collapse:collapse; font-size:11px; text-align:center;">
            <tr>
              <td style="padding:10px 4px;">Home</td>
              <td style="padding:10px 4px;">Keys</td>
              <td style="padding:10px 4px;">Pairing</td>
              <td style="padding:10px 4px; background:#dbeafe; font-weight:700;">Settings</td>
            </tr>
          </table>
        </div>
      </div>
    </td>
  </tr>
</table>

<p><strong>Pairing branch:</strong> Pairing 一覧から QR スキャンへ push 遷移し、結果は SnackBar と前画面復帰で返す。</p>

<table>
  <tr>
    <td style="vertical-align:top;">
      <div style="width:220px; border:1px solid #475569; border-radius:24px; padding:10px; background:#fff7ed; color:#0f172a;">
        <div style="font-size:11px; text-align:center; padding-bottom:8px; color:#475569;">GPG Key Import Navigator.push</div>
        <div style="border:1px solid #cbd5e1; border-radius:16px; background:#ffffff; overflow:hidden; min-height:430px;">
          <div style="padding:12px 14px; background:#e2e8f0; font-weight:700;">GPG鍵インポート</div>
          <div style="padding:14px;">
            <div style="padding:10px 12px; margin-bottom:10px; border:1px solid #cbd5e1; border-radius:12px; background:#f8fafc; font-size:12px; min-height:92px;">-----BEGIN PGP PUBLIC KEY BLOCK-----<br />...</div>
            <div style="display:inline-block; padding:10px 16px; border-radius:999px; background:#2563eb; color:#ffffff; font-size:12px; font-weight:700;">解析</div>
            <div style="margin-top:12px; padding:10px 12px; border:1px solid #cbd5e1; border-radius:12px; font-size:12px;">☑ Ed25519 (主キー)<br />Key ID / Keygrip / 秘密鍵あり</div>
            <div style="margin-top:10px; display:inline-block; padding:10px 16px; border-radius:999px; background:#0f766e; color:#ffffff; font-size:12px; font-weight:700;">インポート (1件)</div>
          </div>
        </div>
      </div>
    </td>
    <td style="vertical-align:top;">
      <div style="width:220px; border:1px solid #475569; border-radius:24px; padding:10px; background:#fff7ed; color:#0f172a;">
        <div style="font-size:11px; text-align:center; padding-bottom:8px; color:#475569;">Sign Request /sign-request/:requestId</div>
        <div style="border:1px solid #cbd5e1; border-radius:16px; background:#ffffff; overflow:hidden; min-height:430px;">
          <div style="padding:12px 14px; background:#e2e8f0; font-weight:700;">署名要求</div>
          <div style="padding:14px;">
            <div style="padding:10px 12px; margin-bottom:12px; border:1px solid #fdba74; border-radius:12px; background:#ffedd5; font-size:12px; font-weight:700;">残り時間 00:52</div>
            <div style="padding:12px; border:1px solid #cbd5e1; border-radius:12px; background:#f8fafc; font-size:12px; min-height:150px;">hash / algorithm / key ID を表示する詳細カード</div>
            <div style="margin-top:18px;">
              <div style="padding:10px 12px; margin-bottom:8px; border-radius:999px; background:#15803d; color:#ffffff; text-align:center; font-size:12px; font-weight:700;">承認</div>
              <div style="padding:10px 12px; margin-bottom:8px; border-radius:999px; background:#b91c1c; color:#ffffff; text-align:center; font-size:12px; font-weight:700;">拒否</div>
              <div style="padding:10px 12px; border:1px solid #cbd5e1; border-radius:999px; text-align:center; font-size:12px; font-weight:700;">無視</div>
            </div>
          </div>
        </div>
      </div>
    </td>
  </tr>
</table>

<p><strong>Overlay screens:</strong> Keys の GPG タブから GPG鍵インポートを開き、FCM 受信時には署名要求画面を一時的に push 表示する。</p>

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
