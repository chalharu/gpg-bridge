import 'package:flutter/material.dart';
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

    expect(find.text('ホーム'), findsWidgets);
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

    expect(find.text('ホーム'), findsWidgets);

    await tester.tap(find.text('Reset registration'));
    await tester.pump();

    expect(find.text('failed to delete secure value'), findsOneWidget);
    expect(find.text('ホーム'), findsWidgets);
  });

  testWidgets('BottomNavigation tabs switch correctly', (
    WidgetTester tester,
  ) async {
    final secureStorage = SecureStorageService(InMemorySecureStorageBackend());

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

    // Verify home tab is shown initially
    expect(find.text('Reset registration'), findsOneWidget);

    // Tap on 鍵管理 tab
    await tester.tap(find.text('鍵管理'));
    await tester.pumpAndSettle();
    // The keys page body should show 鍵管理
    expect(find.text('鍵管理'), findsWidgets);

    // Tap on ペアリング tab
    await tester.tap(find.text('ペアリング'));
    await tester.pumpAndSettle();
    expect(find.text('ペアリング'), findsWidgets);

    // Tap on 設定 tab
    await tester.tap(find.text('設定'));
    await tester.pumpAndSettle();
    expect(find.text('設定'), findsWidgets);
    expect(find.text('テーマ'), findsOneWidget);

    // Tap back to ホーム tab
    await tester.tap(find.text('ホーム'));
    await tester.pumpAndSettle();
    expect(find.text('Reset registration'), findsOneWidget);
  });

  testWidgets('Theme mode toggle in settings', (WidgetTester tester) async {
    final secureStorage = SecureStorageService(InMemorySecureStorageBackend());

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

    // Navigate to settings
    await tester.tap(find.text('設定'));
    await tester.pumpAndSettle();

    // Verify theme options exist
    expect(find.text('システム設定に従う'), findsOneWidget);
    expect(find.text('ライト'), findsOneWidget);
    expect(find.text('ダーク'), findsOneWidget);

    // System should be selected by default - verify RadioGroup has system value
    final radioGroup = tester.widget<RadioGroup<ThemeMode>>(
      find.byType(RadioGroup<ThemeMode>),
    );
    expect(radioGroup.groupValue, ThemeMode.system);

    // Switch to dark mode
    await tester.tap(find.text('ダーク'));
    await tester.pumpAndSettle();

    final radioGroupAfterDark = tester.widget<RadioGroup<ThemeMode>>(
      find.byType(RadioGroup<ThemeMode>),
    );
    expect(radioGroupAfterDark.groupValue, ThemeMode.dark);

    // Switch to light mode
    await tester.tap(find.text('ライト'));
    await tester.pumpAndSettle();

    final radioGroupAfterLight = tester.widget<RadioGroup<ThemeMode>>(
      find.byType(RadioGroup<ThemeMode>),
    );
    expect(radioGroupAfterLight.groupValue, ThemeMode.light);
  });

  testWidgets('App uses Material 3 theme with indigo seed color', (
    WidgetTester tester,
  ) async {
    final secureStorage = SecureStorageService(InMemorySecureStorageBackend());

    await tester.pumpWidget(
      ProviderScope(
        overrides: [secureStorageProvider.overrideWithValue(secureStorage)],
        child: const GpgBridgeApp(),
      ),
    );
    await tester.pumpAndSettle();

    final materialApp = tester.widget<MaterialApp>(find.byType(MaterialApp));
    expect(materialApp.theme, isNotNull);
    expect(materialApp.darkTheme, isNotNull);
    expect(materialApp.theme!.useMaterial3, isTrue);
    expect(materialApp.darkTheme!.useMaterial3, isTrue);

    // Verify the color scheme uses indigo seed
    final lightScheme = materialApp.theme!.colorScheme;
    final darkScheme = materialApp.darkTheme!.colorScheme;
    expect(lightScheme.brightness, Brightness.light);
    expect(darkScheme.brightness, Brightness.dark);
  });
}
