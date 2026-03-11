import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/http/api_config.dart';
import 'package:gpg_bridge_mobile/http/device_api_service.dart';
import 'package:gpg_bridge_mobile/http/server_url_service.dart';
import 'package:gpg_bridge_mobile/pages/register_page.dart';
import 'package:gpg_bridge_mobile/security/secure_storage_service.dart';
import 'package:gpg_bridge_mobile/state/device_registration_service.dart';

import 'helpers/in_memory_secure_storage_backend.dart';

void main() {
  group('RegisterPage', () {
    testWidgets('loads the initial server URL', (tester) async {
      final api = _StubDeviceApiService();
      final registration = _StubDeviceRegistrationService();
      final serverUrlService = _StubRegisterServerUrlService(
        savedValue: 'https://runtime.example.com/api',
      );

      await tester.pumpWidget(
        _buildApp(
          api: api,
          registration: registration,
          serverUrlService: serverUrlService,
        ),
      );
      await tester.pump();

      final editable = tester.widget<EditableText>(find.byType(EditableText));
      expect(editable.controller.text, 'https://runtime.example.com/api');
      expect(find.text('Complete registration'), findsOneWidget);
    });

    testWidgets('falls back to API_BASE_URL when saved URL is invalid', (
      tester,
    ) async {
      final api = _StubDeviceApiService();
      final registration = _StubDeviceRegistrationService();
      final serverUrlService = _StubRegisterServerUrlService(
        savedValue: 'not-a-valid-url',
      );

      await tester.pumpWidget(
        _buildApp(
          api: api,
          registration: registration,
          serverUrlService: serverUrlService,
        ),
      );
      await tester.pump();

      final editable = tester.widget<EditableText>(find.byType(EditableText));
      expect(editable.controller.text, ApiConfig.baseUrl);
      expect(find.text('enter a valid HTTPS server URL'), findsOneWidget);
    });

    testWidgets('disables submit for invalid server URLs', (tester) async {
      final api = _StubDeviceApiService();
      final registration = _StubDeviceRegistrationService();
      final serverUrlService = _StubRegisterServerUrlService(
        savedValue: ApiConfig.baseUrl,
      );

      await tester.pumpWidget(
        _buildApp(
          api: api,
          registration: registration,
          serverUrlService: serverUrlService,
        ),
      );
      await tester.pump();

      await tester.enterText(
        find.byType(TextField),
        'http://runtime.example.com',
      );
      await tester.pump();

      final button = tester.widget<ElevatedButton>(find.byType(ElevatedButton));
      expect(button.onPressed, isNull);
      expect(find.text('server URL must start with https://'), findsOneWidget);
    });

    testWidgets('disables submit for server URLs with query parameters', (
      tester,
    ) async {
      final api = _StubDeviceApiService();
      final registration = _StubDeviceRegistrationService();
      final serverUrlService = _StubRegisterServerUrlService(
        savedValue: ApiConfig.baseUrl,
      );

      await tester.pumpWidget(
        _buildApp(
          api: api,
          registration: registration,
          serverUrlService: serverUrlService,
        ),
      );
      await tester.pump();

      await tester.enterText(
        find.byType(TextField),
        'https://runtime.example.com/api?debug=true',
      );
      await tester.pump();

      final button = tester.widget<ElevatedButton>(find.byType(ElevatedButton));
      expect(button.onPressed, isNull);
      expect(
        find.text('server URL must not include query or fragment'),
        findsOneWidget,
      );
    });

    testWidgets('validates connectivity then registers the device', (
      tester,
    ) async {
      final validationCompleter = Completer<void>();
      final api = _StubDeviceApiService(
        validateHandler: ({required serverUrl}) => validationCompleter.future,
      );
      final registration = _StubDeviceRegistrationService();
      final serverUrlService = _StubRegisterServerUrlService(
        savedValue: 'https://runtime.example.com/api',
      );

      await tester.pumpWidget(
        _buildApp(
          api: api,
          registration: registration,
          serverUrlService: serverUrlService,
        ),
      );
      await tester.pump();

      await tester.tap(find.text('Complete registration'));
      await tester.pump();

      expect(find.byType(CircularProgressIndicator), findsOneWidget);
      expect(
        find.text('Registering with https://runtime.example.com/api'),
        findsOneWidget,
      );

      validationCompleter.complete();
      await tester.pumpAndSettle();

      expect(api.validatedUrls, ['https://runtime.example.com/api']);
      expect(registration.registeredUrls, ['https://runtime.example.com/api']);
      expect(registration.startTokenRefreshListenerCallCount, 1);
      expect(
        find.text('Connected to https://runtime.example.com/api'),
        findsOneWidget,
      );
    });

    testWidgets('shows an error snackbar when validation fails', (
      tester,
    ) async {
      final api = _StubDeviceApiService(
        validateHandler: ({required serverUrl}) async {
          throw DeviceApiException('health check failed');
        },
      );
      final registration = _StubDeviceRegistrationService();
      final serverUrlService = _StubRegisterServerUrlService(
        savedValue: 'https://runtime.example.com/api',
      );

      await tester.pumpWidget(
        _buildApp(
          api: api,
          registration: registration,
          serverUrlService: serverUrlService,
        ),
      );
      await tester.pump();

      await tester.tap(find.text('Complete registration'));
      await tester.pumpAndSettle();

      expect(
        find.text('Unable to reach https://runtime.example.com/api'),
        findsOneWidget,
      );
      expect(find.text('health check failed'), findsOneWidget);
      expect(registration.registeredUrls, isEmpty);
      expect(registration.startTokenRefreshListenerCallCount, 0);
    });
  });
}

Widget _buildApp({
  required DeviceApiService api,
  required DeviceRegistrationService registration,
  required ServerUrlService serverUrlService,
}) {
  return ProviderScope(
    overrides: [
      deviceApiProvider.overrideWithValue(api),
      deviceRegistrationProvider.overrideWithValue(registration),
      serverUrlServiceProvider.overrideWithValue(serverUrlService),
    ],
    child: const MaterialApp(home: RegisterPage()),
  );
}

class _StubRegisterServerUrlService implements ServerUrlService {
  _StubRegisterServerUrlService({this.savedValue});

  final String? savedValue;
  late final SecureStorageService _storageService = SecureStorageService(
    InMemorySecureStorageBackend(),
  );
  late final DefaultServerUrlService _delegate = DefaultServerUrlService(
    _storageService,
  );

  @override
  String buildEndpointUrl({required String baseUrl, required String path}) {
    return _delegate.buildEndpointUrl(baseUrl: baseUrl, path: path);
  }

  @override
  Future<void> clear() {
    return _delegate.clear();
  }

  @override
  Future<String> getSavedOrDefault() async {
    if (savedValue != null) {
      await _storageService.writeValue(
        key: SecureStorageKeys.serverUrl,
        value: savedValue!,
      );
    }
    return _delegate.getSavedOrDefault();
  }

  @override
  String normalize(String input) {
    return _delegate.normalize(input);
  }

  @override
  Future<void> save(String serverUrl) {
    return _delegate.save(serverUrl);
  }
}

class _StubDeviceRegistrationService implements DeviceRegistrationService {
  final List<String> registeredUrls = [];
  int startTokenRefreshListenerCallCount = 0;

  @override
  Future<void> checkAndRefreshDeviceJwt() async {}

  @override
  Future<void> checkAndRefreshFcmToken() async {}

  @override
  Future<void> register({required String serverUrl}) async {
    registeredUrls.add(serverUrl);
  }

  @override
  void startTokenRefreshListener() {
    startTokenRefreshListenerCallCount += 1;
  }

  @override
  Future<void> unregister() async {}
}

class _StubDeviceApiService implements DeviceApiService {
  _StubDeviceApiService({this.validateHandler});

  final Future<void> Function({required String serverUrl})? validateHandler;
  final List<String> validatedUrls = [];

  @override
  Future<void> deleteDevice() async {}

  @override
  Future<DeviceRefreshResponse> refreshDeviceJwt({
    required String currentDeviceJwt,
  }) {
    throw UnimplementedError();
  }

  @override
  Future<DeviceResponse> registerDevice({
    required String serverUrl,
    required String deviceToken,
    required String firebaseInstallationId,
    required List<Map<String, dynamic>> sigKeys,
    required List<Map<String, dynamic>> encKeys,
    String? defaultKid,
  }) {
    throw UnimplementedError();
  }

  @override
  Future<void> updateDevice({String? deviceToken, String? defaultKid}) async {}

  @override
  Future<void> validateServerConnection({required String serverUrl}) async {
    validatedUrls.add(serverUrl);
    await validateHandler?.call(serverUrl: serverUrl);
  }
}
