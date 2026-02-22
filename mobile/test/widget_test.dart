import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'package:gpg_bridge_mobile/main.dart';
import 'package:gpg_bridge_mobile/security/secure_storage_service.dart';
import 'package:gpg_bridge_mobile/state/auth_state.dart';

import 'helpers/in_memory_secure_storage_backend.dart';
import 'helpers/throwing_secure_storage_backend.dart';

void main() {
  testWidgets('Registration flow routes to home', (WidgetTester tester) async {
    final secureStorage = SecureStorageService(InMemorySecureStorageBackend());

    await tester.pumpWidget(
      ProviderScope(
        overrides: [secureStorageProvider.overrideWithValue(secureStorage)],
        child: const GpgBridgeApp(),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('Register'), findsOneWidget);
    expect(find.text('Complete registration'), findsOneWidget);

    await tester.tap(find.text('Complete registration'));
    await tester.pumpAndSettle();

    expect(find.text('Home'), findsOneWidget);
    expect(find.text('Reset registration'), findsOneWidget);
  });

  testWidgets('Shows snackbar when registration storage write fails', (
    WidgetTester tester,
  ) async {
    final secureStorage = SecureStorageService(ThrowingSecureStorageBackend());

    await tester.pumpWidget(
      ProviderScope(
        overrides: [secureStorageProvider.overrideWithValue(secureStorage)],
        child: const GpgBridgeApp(),
      ),
    );
    await tester.pumpAndSettle();

    await tester.tap(find.text('Complete registration'));
    await tester.pump();

    expect(find.text('failed to write secure value'), findsOneWidget);
    expect(find.text('Register'), findsOneWidget);
  });

  testWidgets('Shows snackbar when reset storage delete fails', (
    WidgetTester tester,
  ) async {
    final secureStorage = SecureStorageService(ThrowingSecureStorageBackend());

    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          secureStorageProvider.overrideWithValue(secureStorage),
          authStateProvider.overrideWithValue(true),
        ],
        child: const GpgBridgeApp(),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('Home'), findsOneWidget);

    await tester.tap(find.text('Reset registration'));
    await tester.pump();

    expect(find.text('failed to delete secure value'), findsOneWidget);
    expect(find.text('Home'), findsOneWidget);
  });
}
