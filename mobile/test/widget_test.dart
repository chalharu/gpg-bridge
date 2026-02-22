import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'package:gpg_bridge_mobile/main.dart';
import 'package:gpg_bridge_mobile/security/secure_storage_service.dart';

class _InMemorySecureStorageBackend implements SecureStorageBackend {
  final Map<String, String> _values = <String, String>{};

  @override
  Future<void> write({required String key, required String value}) async {
    _values[key] = value;
  }

  @override
  Future<String?> read({required String key}) async {
    return _values[key];
  }

  @override
  Future<void> delete({required String key}) async {
    _values.remove(key);
  }
}

void main() {
  testWidgets('Registration flow routes to home', (WidgetTester tester) async {
    final secureStorage = SecureStorageService(_InMemorySecureStorageBackend());

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
}
