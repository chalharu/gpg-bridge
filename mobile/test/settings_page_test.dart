import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/http/server_url_service.dart';
import 'package:gpg_bridge_mobile/pages/settings_page.dart';
import 'package:gpg_bridge_mobile/state/theme_mode_state.dart';

void main() {
  group('SettingsPage', () {
    testWidgets('shows the saved server URL', (tester) async {
      final container = ProviderContainer(
        overrides: [
          settingsServerUrlProvider.overrideWithValue(
            const AsyncValue.data('https://runtime.example.com/api'),
          ),
        ],
      );
      addTearDown(container.dispose);

      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: const MaterialApp(home: SettingsPage()),
        ),
      );
      await tester.pump();

      expect(find.text('接続サーバー'), findsOneWidget);
      expect(find.text('https://runtime.example.com/api'), findsOneWidget);
    });

    testWidgets('shows an error message when server URL loading fails', (
      tester,
    ) async {
      final container = ProviderContainer(
        overrides: [
          settingsServerUrlProvider.overrideWithValue(
            AsyncValue.error(ServerUrlException('broken'), StackTrace.empty),
          ),
        ],
      );
      addTearDown(container.dispose);

      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: const MaterialApp(home: SettingsPage()),
        ),
      );

      expect(find.text('接続サーバーを取得できませんでした'), findsOneWidget);
    });

    testWidgets('updates theme mode from the radio list', (tester) async {
      final container = ProviderContainer(
        overrides: [
          settingsServerUrlProvider.overrideWithValue(
            const AsyncValue.data('https://runtime.example.com/api'),
          ),
        ],
      );
      addTearDown(container.dispose);

      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: const MaterialApp(home: SettingsPage()),
        ),
      );
      await tester.pump();

      await tester.tap(find.text('ライト'));
      await tester.pump();

      expect(container.read(themeModeStateProvider), ThemeMode.light);
    });
  });
}
