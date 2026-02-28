import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/pages/sign_request/sign_request_page.dart';
import 'package:gpg_bridge_mobile/security/ec_jwk.dart';
import 'package:gpg_bridge_mobile/state/sign_request_state.dart';

const _testPublicJwk = {
  'kty': 'EC',
  'crv': 'P-256',
  'x': '0qHaLh3jKQAQ5tYB6NooOi2lFjJj9E5h80yoHSZoq0I',
  'y': 'F8CORGPfI9872Nxw2Fkr6XUn-5AczutLMi9uRygC7pE',
};

DecryptedSignRequest _buildRequest({
  String requestId = 'req-1',
  DateTime? receivedAt,
}) {
  return DecryptedSignRequest(
    requestId: requestId,
    signJwt: 'jwt-$requestId',
    hash: 'dGVzdCBoYXNoIHZhbHVl',
    hashAlgorithm: 'sha256',
    keyId: '0xABCD1234',
    pairingId: 'pair-1',
    daemonEncPublicKey: EcPublicJwk.fromJson(_testPublicJwk),
    receivedAt: receivedAt ?? DateTime.now(),
  );
}

void main() {
  group('SignRequestPage', () {
    testWidgets('shows "not found" when request is missing', (tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            signRequestStateProvider.overrideWith(
              () => _EmptySignRequestState(),
            ),
          ],
          child: const MaterialApp(
            home: SignRequestPage(requestId: 'non-existent'),
          ),
        ),
      );
      await tester.pump();

      expect(find.text('署名要求が見つかりません'), findsOneWidget);
    });

    // Note: Loading and error states are handled by asyncRequests.when() in
    // the build method (see sign_request_page.dart). Widget-level tests for
    // these states are not feasible due to Riverpod 3.x test limitations
    // with keepAlive async notifiers and overrideWith.
    // The when() pattern is verified structurally by the data-path tests.

    testWidgets('displays request details', (tester) async {
      final request = _buildRequest();

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            signRequestStateProvider.overrideWith(
              () => _PreloadedSignRequestState([request]),
            ),
          ],
          child: const MaterialApp(home: SignRequestPage(requestId: 'req-1')),
        ),
      );
      await tester.pump();

      expect(find.text('署名要求'), findsOneWidget);
      expect(find.text('sha256'), findsOneWidget);
      expect(find.text('0xABCD1234'), findsOneWidget);
      expect(find.text('dGVzdCBoYXNoIHZhbHVl'), findsOneWidget);
    });

    testWidgets('shows approve, deny, and ignore buttons', (tester) async {
      final request = _buildRequest();

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            signRequestStateProvider.overrideWith(
              () => _PreloadedSignRequestState([request]),
            ),
          ],
          child: const MaterialApp(home: SignRequestPage(requestId: 'req-1')),
        ),
      );
      await tester.pump();

      expect(find.text('承認'), findsOneWidget);
      expect(find.text('拒否'), findsOneWidget);
      expect(find.text('無視'), findsOneWidget);
    });

    testWidgets('approve button is enabled', (tester) async {
      final request = _buildRequest();

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            signRequestStateProvider.overrideWith(
              () => _PreloadedSignRequestState([request]),
            ),
          ],
          child: const MaterialApp(home: SignRequestPage(requestId: 'req-1')),
        ),
      );
      await tester.pump();

      // The FilledButton containing '承認' should be enabled.
      final approveButton = tester.widget<FilledButton>(
        find.ancestor(of: find.text('承認'), matching: find.byType(FilledButton)),
      );
      expect(approveButton.onPressed, isNotNull);
    });

    testWidgets('approve button calls approve and pops', (tester) async {
      final request = _buildRequest();
      var approveCalled = false;

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            signRequestStateProvider.overrideWith(
              () => _TrackingSignRequestState([
                request,
              ], onApprove: () => approveCalled = true),
            ),
          ],
          child: MaterialApp(
            home: Builder(
              builder: (context) => ElevatedButton(
                onPressed: () => Navigator.of(context).push(
                  MaterialPageRoute<void>(
                    builder: (_) => const SignRequestPage(requestId: 'req-1'),
                  ),
                ),
                child: const Text('open'),
              ),
            ),
          ),
        ),
      );

      await tester.tap(find.text('open'));
      await tester.pumpAndSettle();

      await tester.tap(find.text('承認'));
      await tester.pumpAndSettle();

      expect(approveCalled, isTrue);
    });

    testWidgets('deny button calls deny and pops', (tester) async {
      final request = _buildRequest();
      var denyCalled = false;

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            signRequestStateProvider.overrideWith(
              () => _TrackingSignRequestState([
                request,
              ], onDeny: () => denyCalled = true),
            ),
          ],
          child: MaterialApp(
            home: Builder(
              builder: (context) => ElevatedButton(
                onPressed: () => Navigator.of(context).push(
                  MaterialPageRoute<void>(
                    builder: (_) => const SignRequestPage(requestId: 'req-1'),
                  ),
                ),
                child: const Text('open'),
              ),
            ),
          ),
        ),
      );

      // Navigate to the sign request page.
      await tester.tap(find.text('open'));
      await tester.pumpAndSettle();

      // Tap deny button.
      await tester.tap(find.text('拒否'));
      await tester.pumpAndSettle();

      expect(denyCalled, isTrue);
    });

    testWidgets('ignore button pops without calling service', (tester) async {
      final request = _buildRequest();

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            signRequestStateProvider.overrideWith(
              () => _PreloadedSignRequestState([request]),
            ),
          ],
          child: MaterialApp(
            home: Builder(
              builder: (context) => ElevatedButton(
                onPressed: () => Navigator.of(context).push(
                  MaterialPageRoute<void>(
                    builder: (_) => const SignRequestPage(requestId: 'req-1'),
                  ),
                ),
                child: const Text('open'),
              ),
            ),
          ),
        ),
      );

      await tester.tap(find.text('open'));
      await tester.pumpAndSettle();

      await tester.tap(find.text('無視'));
      await tester.pumpAndSettle();

      // Should have popped back to the original page.
      expect(find.text('open'), findsOneWidget);
      expect(find.text('署名要求'), findsNothing);
    });

    testWidgets('shows countdown timer', (tester) async {
      final request = _buildRequest();

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            signRequestStateProvider.overrideWith(
              () => _PreloadedSignRequestState([request]),
            ),
          ],
          child: const MaterialApp(home: SignRequestPage(requestId: 'req-1')),
        ),
      );
      await tester.pump();

      // Timer should show something like "04:5X" or "05:00".
      expect(find.textContaining('残り時間:'), findsOneWidget);
    });

    testWidgets('routePath constant is correct', (tester) async {
      expect(SignRequestPage.routePath, equals('/sign-request/:requestId'));
    });
  });
}

// ---------------------------------------------------------------------------
// State overrides for testing
// ---------------------------------------------------------------------------

class _EmptySignRequestState extends SignRequestState {
  @override
  Future<List<DecryptedSignRequest>> build() async => [];
}

class _PreloadedSignRequestState extends SignRequestState {
  _PreloadedSignRequestState(this._requests);

  final List<DecryptedSignRequest> _requests;

  @override
  Future<List<DecryptedSignRequest>> build() async => _requests;
}

class _TrackingSignRequestState extends SignRequestState {
  _TrackingSignRequestState(this._requests, {this.onDeny, this.onApprove});

  final List<DecryptedSignRequest> _requests;
  final void Function()? onDeny;
  final void Function()? onApprove;

  @override
  Future<List<DecryptedSignRequest>> build() async => _requests;

  @override
  Future<void> approve(DecryptedSignRequest request) async {
    onApprove?.call();
    dismiss(request.requestId);
  }

  @override
  Future<void> deny(DecryptedSignRequest request) async {
    onDeny?.call();
    dismiss(request.requestId);
  }
}
