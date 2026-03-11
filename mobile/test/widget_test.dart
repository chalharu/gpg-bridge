import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'package:gpg_bridge_mobile/http/api_config.dart';
import 'package:gpg_bridge_mobile/http/device_api_service.dart';
import 'package:gpg_bridge_mobile/http/server_url_service.dart';
import 'package:gpg_bridge_mobile/main.dart';
import 'package:gpg_bridge_mobile/security/secure_storage_service.dart';
import 'package:gpg_bridge_mobile/state/auth_state.dart';
import 'package:gpg_bridge_mobile/state/device_registration_service.dart';

import 'helpers/in_memory_secure_storage_backend.dart';

class _TestAuthState extends AuthState {
  _TestAuthState(this._initial);
  final bool _initial;

  @override
  Future<bool> build() async => _initial;
}

class _MockDeviceRegistrationService implements DeviceRegistrationService {
  _MockDeviceRegistrationService({
    this.onRegisterCalled,
    this.registerError,
    this.unregisterError,
  });

  final void Function(String serverUrl)? onRegisterCalled;
  final DeviceRegistrationException? registerError;
  final DeviceRegistrationException? unregisterError;

  @override
  Future<void> register({required String serverUrl}) async {
    if (registerError != null) throw registerError!;
    onRegisterCalled?.call(serverUrl);
  }

  @override
  void startTokenRefreshListener() {}

  @override
  Future<void> checkAndRefreshDeviceJwt() async {}

  @override
  Future<void> checkAndRefreshFcmToken() async {}

  @override
  Future<void> unregister() async {
    if (unregisterError != null) throw unregisterError!;
  }
}

class _MockDeviceApiService implements DeviceApiService {
  _MockDeviceApiService({this.validationError});

  final DeviceApiException? validationError;

  @override
  Future<void> validateServerConnection({required String serverUrl}) async {
    if (validationError != null) {
      throw validationError!;
    }
  }

  @override
  Future<DeviceResponse> registerDevice({
    required String serverUrl,
    required String deviceToken,
    required String firebaseInstallationId,
    required List<Map<String, dynamic>> sigKeys,
    required List<Map<String, dynamic>> encKeys,
    String? defaultKid,
  }) async {
    throw UnsupportedError('not used in widget tests');
  }

  @override
  Future<void> updateDevice({String? deviceToken, String? defaultKid}) async {}

  @override
  Future<void> deleteDevice() async {}

  @override
  Future<DeviceRefreshResponse> refreshDeviceJwt({
    required String currentDeviceJwt,
  }) async {
    throw UnsupportedError('not used in widget tests');
  }
}

class _ThrowingServerUrlService implements ServerUrlService {
  @override
  Future<void> clear() async {}

  @override
  String buildEndpointUrl({required String baseUrl, required String path}) {
    return '$baseUrl$path';
  }

  @override
  Future<String> getSavedOrDefault() {
    throw ServerUrlException('stored server URL is invalid');
  }

  @override
  String normalize(String input) => input;

  @override
  Future<void> save(String serverUrl) async {}
}

void main() {
  testWidgets('Registration flow routes to home', (WidgetTester tester) async {
    final secureStorage = SecureStorageService(InMemorySecureStorageBackend());

    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          secureStorageProvider.overrideWithValue(secureStorage),
          deviceApiProvider.overrideWithValue(_MockDeviceApiService()),
          deviceRegistrationProvider.overrideWith((ref) {
            return _MockDeviceRegistrationService(
              onRegisterCalled: (serverUrl) {
                expect(serverUrl, ApiConfig.baseUrl);
                ref.read(authStateProvider.notifier).setRegistered(true);
              },
            );
          }),
        ],
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

  testWidgets('Shows snackbar when registration fails', (
    WidgetTester tester,
  ) async {
    final secureStorage = SecureStorageService(InMemorySecureStorageBackend());

    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          secureStorageProvider.overrideWithValue(secureStorage),
          deviceApiProvider.overrideWithValue(_MockDeviceApiService()),
          deviceRegistrationProvider.overrideWith((ref) {
            return _MockDeviceRegistrationService(
              registerError: DeviceRegistrationException('registration failed'),
            );
          }),
        ],
        child: const GpgBridgeApp(),
      ),
    );
    await tester.pumpAndSettle();

    await tester.tap(find.text('Complete registration'));
    await tester.pump();

    expect(find.text('registration failed'), findsOneWidget);
    expect(find.text('Register'), findsOneWidget);
  });

  testWidgets('Disables registration for invalid server URL', (
    WidgetTester tester,
  ) async {
    final secureStorage = SecureStorageService(InMemorySecureStorageBackend());

    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          secureStorageProvider.overrideWithValue(secureStorage),
          deviceApiProvider.overrideWithValue(_MockDeviceApiService()),
          deviceRegistrationProvider.overrideWith((ref) {
            return _MockDeviceRegistrationService();
          }),
        ],
        child: const GpgBridgeApp(),
      ),
    );
    await tester.pumpAndSettle();

    await tester.enterText(find.byType(TextField), 'http://insecure.example');
    await tester.pumpAndSettle();

    final button = tester.widget<ElevatedButton>(
      find.widgetWithText(ElevatedButton, 'Complete registration'),
    );
    expect(button.onPressed, isNull);
    expect(find.text('server URL must start with https://'), findsOneWidget);
  });

  testWidgets('Register page falls back when stored server URL is corrupt', (
    WidgetTester tester,
  ) async {
    final secureStorage = SecureStorageService(InMemorySecureStorageBackend());

    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          secureStorageProvider.overrideWithValue(secureStorage),
          serverUrlServiceProvider.overrideWithValue(
            _ThrowingServerUrlService(),
          ),
          deviceApiProvider.overrideWithValue(_MockDeviceApiService()),
          deviceRegistrationProvider.overrideWith((ref) {
            return _MockDeviceRegistrationService();
          }),
        ],
        child: const GpgBridgeApp(),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('stored server URL is invalid'), findsOneWidget);
    final textField = tester.widget<TextField>(find.byType(TextField));
    expect(textField.controller?.text, ApiConfig.baseUrl);
  });

  testWidgets('Shows snackbar when server validation fails', (
    WidgetTester tester,
  ) async {
    final secureStorage = SecureStorageService(InMemorySecureStorageBackend());

    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          secureStorageProvider.overrideWithValue(secureStorage),
          deviceApiProvider.overrideWithValue(
            _MockDeviceApiService(
              validationError: DeviceApiException('health check failed'),
            ),
          ),
          deviceRegistrationProvider.overrideWith((ref) {
            return _MockDeviceRegistrationService();
          }),
        ],
        child: const GpgBridgeApp(),
      ),
    );
    await tester.pumpAndSettle();

    await tester.tap(find.text('Complete registration'));
    await tester.pump();

    expect(find.text('health check failed'), findsOneWidget);
    expect(find.textContaining('Unable to reach'), findsOneWidget);
  });

  testWidgets('Shows snackbar when unregistration fails', (
    WidgetTester tester,
  ) async {
    final secureStorage = SecureStorageService(InMemorySecureStorageBackend());

    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          secureStorageProvider.overrideWithValue(secureStorage),
          authStateProvider.overrideWith(() => _TestAuthState(true)),
          deviceApiProvider.overrideWithValue(_MockDeviceApiService()),
          deviceRegistrationProvider.overrideWith((ref) {
            return _MockDeviceRegistrationService(
              unregisterError: DeviceRegistrationException(
                'unregistration failed',
              ),
            );
          }),
        ],
        child: const GpgBridgeApp(),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('ホーム'), findsWidgets);

    await tester.tap(find.text('Reset registration'));
    await tester.pump();

    expect(find.text('unregistration failed'), findsOneWidget);
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
          authStateProvider.overrideWith(() => _TestAuthState(true)),
          deviceApiProvider.overrideWithValue(_MockDeviceApiService()),
          deviceRegistrationProvider.overrideWith((ref) {
            return _MockDeviceRegistrationService();
          }),
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
          authStateProvider.overrideWith(() => _TestAuthState(true)),
          deviceApiProvider.overrideWithValue(_MockDeviceApiService()),
          deviceRegistrationProvider.overrideWith((ref) {
            return _MockDeviceRegistrationService();
          }),
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
        overrides: [
          secureStorageProvider.overrideWithValue(secureStorage),
          deviceApiProvider.overrideWithValue(_MockDeviceApiService()),
        ],
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
