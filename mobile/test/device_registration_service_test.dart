import 'dart:async';
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/fcm/fcm_token_service.dart';
import 'package:gpg_bridge_mobile/http/device_api_service.dart';
import 'package:gpg_bridge_mobile/security/crypto_utils.dart';
import 'package:gpg_bridge_mobile/security/keystore_platform_service.dart';
import 'package:gpg_bridge_mobile/security/secure_storage_service.dart';
import 'package:gpg_bridge_mobile/state/device_registration_service.dart';
import 'package:gpg_bridge_mobile/state/fid_service.dart';

import 'helpers/in_memory_secure_storage_backend.dart';

void main() {
  group('DeviceRegistrationException', () {
    test('toString includes message without cause', () {
      final error = DeviceRegistrationException('reg failed');

      expect(error.toString(), 'DeviceRegistrationException: reg failed');
    });

    test('toString includes message and cause', () {
      final error = DeviceRegistrationException(
        'reg failed',
        cause: Exception('inner'),
      );

      expect(error.toString(), contains('reg failed'));
      expect(error.toString(), contains('inner'));
    });
  });

  group('DefaultDeviceRegistrationService', () {
    late _MockKeystorePlatformService mockKeystore;
    late _MockFcmTokenProvider mockFcm;
    late _MockFidProvider mockFid;
    late _MockDeviceApiService mockApi;
    late SecureStorageService storageService;
    late InMemorySecureStorageBackend storageBackend;
    late bool registeredState;

    setUp(() {
      mockKeystore = _MockKeystorePlatformService();
      mockFcm = _MockFcmTokenProvider(token: 'fcm-token-123');
      mockFid = _MockFidProvider(fid: 'fid-abc');
      mockApi = _MockDeviceApiService();
      storageBackend = InMemorySecureStorageBackend();
      storageService = SecureStorageService(storageBackend);
      registeredState = false;
    });

    DefaultDeviceRegistrationService createService({
      _MockFcmTokenProvider? fcm,
    }) {
      return DefaultDeviceRegistrationService(
        keystoreService: mockKeystore,
        fcmTokenService: fcm ?? mockFcm,
        fidService: mockFid,
        deviceApiService: mockApi,
        storageService: storageService,
        onRegistrationChanged: (v) => registeredState = v,
      );
    }

    test(
      'register generates keys, calls API, and stores credentials',
      () async {
        final service = createService();

        await service.register();

        // Keys generated for both aliases.
        expect(mockKeystore.generatedAliases, contains('device_key'));
        expect(mockKeystore.generatedAliases, contains('e2e_key'));

        // API called with correct data.
        expect(mockApi.registerCalled, isTrue);
        expect(mockApi.lastRegisterDeviceToken, 'fcm-token-123');
        expect(mockApi.lastRegisterFid, 'fid-abc');

        // Credentials stored.
        expect(
          await storageService.readValue(key: SecureStorageKeys.deviceJwt),
          'mock-device-jwt',
        );
        expect(
          await storageService.readValue(key: SecureStorageKeys.deviceId),
          'fid-abc',
        );
        expect(
          await storageService.readValue(key: SecureStorageKeys.fcmToken),
          'fcm-token-123',
        );

        // Auth state updated.
        expect(registeredState, isTrue);
      },
    );

    test('register wraps errors in DeviceRegistrationException', () async {
      mockApi.shouldFail = true;
      final service = createService();

      expect(
        () => service.register(),
        throwsA(isA<DeviceRegistrationException>()),
      );
    });

    test('unregister calls DELETE and clears storage', () async {
      final service = createService();

      // First register to populate storage.
      await service.register();
      expect(registeredState, isTrue);

      // Now unregister.
      await service.unregister();

      expect(mockApi.deleteCalled, isTrue);
      expect(
        await storageService.readValue(key: SecureStorageKeys.deviceJwt),
        isNull,
      );
      expect(
        await storageService.readValue(key: SecureStorageKeys.deviceId),
        isNull,
      );
      expect(
        await storageService.readValue(key: SecureStorageKeys.fcmToken),
        isNull,
      );
      expect(registeredState, isFalse);
    });

    test('unregister wraps errors in DeviceRegistrationException', () async {
      mockApi.deleteShouldFail = true;
      final service = createService();

      expect(
        () => service.unregister(),
        throwsA(isA<DeviceRegistrationException>()),
      );
    });

    test('token refresh listener calls PATCH on new token', () async {
      final controller = StreamController<String>.broadcast();
      final fcmWithRefresh = _MockFcmTokenProvider(
        token: 'fcm-initial',
        refreshStream: controller.stream,
      );
      final service = createService(fcm: fcmWithRefresh);

      // Register first to store the initial token.
      await service.register();
      service.startTokenRefreshListener();

      // Emit a new token.
      controller.add('fcm-refreshed');
      await Future<void>.delayed(const Duration(milliseconds: 50));

      expect(mockApi.updateCalled, isTrue);
      expect(mockApi.lastUpdateDeviceToken, 'fcm-refreshed');

      // Verify cached token is updated.
      expect(
        await storageService.readValue(key: SecureStorageKeys.fcmToken),
        'fcm-refreshed',
      );

      await controller.close();
    });

    test('token refresh skips PATCH when token unchanged', () async {
      final controller = StreamController<String>.broadcast();
      final fcmWithRefresh = _MockFcmTokenProvider(
        token: 'fcm-initial',
        refreshStream: controller.stream,
      );
      final service = createService(fcm: fcmWithRefresh);

      await service.register();
      service.startTokenRefreshListener();

      // Emit the same token — should not call PATCH.
      controller.add('fcm-initial');
      await Future<void>.delayed(const Duration(milliseconds: 50));

      expect(mockApi.updateCalled, isFalse);

      await controller.close();
    });

    test('startTokenRefreshListener is idempotent', () async {
      final controller = StreamController<String>.broadcast();
      final fcmWithRefresh = _MockFcmTokenProvider(
        token: 'fcm-initial',
        refreshStream: controller.stream,
      );
      final service = createService(fcm: fcmWithRefresh);

      await service.register();
      service.startTokenRefreshListener();
      service.startTokenRefreshListener(); // called twice

      controller.add('fcm-new');
      await Future<void>.delayed(const Duration(milliseconds: 50));

      // Only one PATCH should have been made, not two.
      expect(mockApi.updateCallCount, 1);

      await controller.close();
    });

    test('checkAndRefreshDeviceJwt returns early if no JWT stored', () async {
      final service = createService();

      // Don't register — no JWT in storage.
      await service.checkAndRefreshDeviceJwt();

      expect(mockApi.refreshJwtCalled, isFalse);
    });

    test(
      'checkAndRefreshDeviceJwt calls refresh when remaining < 1/3',
      () async {
        final service = createService();

        final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
        // totalValidity = 7200, remaining = 100 → 100 < 7200/3 = 2400
        final jwt = _buildFakeJwt(iat: now - 7100, exp: now + 100);
        await storageService.writeValue(
          key: SecureStorageKeys.deviceJwt,
          value: jwt,
        );

        await service.checkAndRefreshDeviceJwt();

        expect(mockApi.refreshJwtCalled, isTrue);
      },
    );

    test(
      'checkAndRefreshDeviceJwt does nothing when remaining >= 1/3',
      () async {
        final service = createService();

        final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
        // totalValidity = 7200, remaining = 6000 → 6000 >= 7200/3 = 2400
        final jwt = _buildFakeJwt(iat: now - 1200, exp: now + 6000);
        await storageService.writeValue(
          key: SecureStorageKeys.deviceJwt,
          value: jwt,
        );

        await service.checkAndRefreshDeviceJwt();

        expect(mockApi.refreshJwtCalled, isFalse);
      },
    );

    test('checkAndRefreshDeviceJwt clears auth when JWT is expired', () async {
      final service = createService();

      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      // Expired: remaining = -100
      final jwt = _buildFakeJwt(iat: now - 7300, exp: now - 100);
      await storageService.writeValue(
        key: SecureStorageKeys.deviceJwt,
        value: jwt,
      );

      await service.checkAndRefreshDeviceJwt();

      // JWT should be deleted from storage.
      expect(
        await storageService.readValue(key: SecureStorageKeys.deviceJwt),
        isNull,
      );
      // Auth state should be false (via onRegistrationChanged callback).
      expect(registeredState, isFalse);
      // Refresh API should NOT have been called.
      expect(mockApi.refreshJwtCalled, isFalse);
    });

    test('checkAndRefreshFcmToken returns early if no token stored', () async {
      final service = createService();

      await service.checkAndRefreshFcmToken();

      expect(mockApi.updateCalled, isFalse);
    });

    test('checkAndRefreshFcmToken calls PATCH when token differs', () async {
      final service = createService();

      // Simulate stored token different from current FCM token.
      await storageService.writeValue(
        key: SecureStorageKeys.fcmToken,
        value: 'old-token',
      );

      await service.checkAndRefreshFcmToken();

      expect(mockApi.updateCalled, isTrue);
      expect(mockApi.lastUpdateDeviceToken, 'fcm-token-123');
      expect(
        await storageService.readValue(key: SecureStorageKeys.fcmToken),
        'fcm-token-123',
      );
    });

    test('checkAndRefreshFcmToken skips PATCH when token unchanged', () async {
      final fcmSameToken = _MockFcmTokenProvider(token: 'same-token');
      final service = createService(fcm: fcmSameToken);

      await storageService.writeValue(
        key: SecureStorageKeys.fcmToken,
        value: 'same-token',
      );

      await service.checkAndRefreshFcmToken();

      expect(mockApi.updateCalled, isFalse);
    });
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

String _buildFakeJwt({required int iat, required int exp}) {
  final header = base64Url
      .encode(utf8.encode(jsonEncode({'alg': 'ES256', 'typ': 'JWT'})))
      .replaceAll('=', '');
  final payload = base64Url
      .encode(utf8.encode(jsonEncode({'iat': iat, 'exp': exp, 'sub': 'test'})))
      .replaceAll('=', '');
  return '$header.$payload.fake-sig';
}

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

class _MockKeystorePlatformService implements KeystorePlatformService {
  final List<String> generatedAliases = [];

  @override
  Future<void> generateKeyPair({required String alias}) async {
    generatedAliases.add(alias);
  }

  @override
  Future<String> sign({required String alias, required List<int> data}) async {
    return base64Encode(List.filled(64, 0xAB));
  }

  @override
  Future<bool> verify({
    required String alias,
    required List<int> data,
    required String signatureBase64,
  }) async {
    return true;
  }

  @override
  Future<Map<String, String>> getPublicKeyJwk({required String alias}) async {
    final use = alias == KeystoreAliases.deviceKey ? 'sig' : 'enc';
    final alg = alias == KeystoreAliases.deviceKey ? 'ES256' : 'ECDH-ES+A256KW';
    return {
      'kty': 'EC',
      'crv': 'P-256',
      'use': use,
      'alg': alg,
      'x': base64UrlEncode(List.filled(32, 0x01)),
      'y': base64UrlEncode(List.filled(32, 0x02)),
    };
  }
}

class _MockFcmTokenProvider implements FcmTokenService {
  _MockFcmTokenProvider({required this.token, Stream<String>? refreshStream})
    : _refreshStream = refreshStream ?? const Stream<String>.empty();

  final String token;
  final Stream<String> _refreshStream;

  @override
  Future<String> getToken() async => token;

  @override
  Stream<String> get onTokenRefresh => _refreshStream;
}

class _MockFidProvider implements FidService {
  _MockFidProvider({required this.fid});

  final String fid;

  @override
  Future<String> getId() async => fid;
}

class _MockDeviceApiService implements DeviceApiService {
  bool registerCalled = false;
  bool updateCalled = false;
  int updateCallCount = 0;
  bool deleteCalled = false;
  bool shouldFail = false;
  bool deleteShouldFail = false;
  bool refreshJwtCalled = false;
  String? lastRegisterDeviceToken;
  String? lastRegisterFid;
  String? lastUpdateDeviceToken;

  @override
  Future<DeviceResponse> registerDevice({
    required String deviceToken,
    required String firebaseInstallationId,
    required List<Map<String, dynamic>> sigKeys,
    required List<Map<String, dynamic>> encKeys,
    String? defaultKid,
  }) async {
    if (shouldFail) throw DeviceApiException('mock register failure');
    registerCalled = true;
    lastRegisterDeviceToken = deviceToken;
    lastRegisterFid = firebaseInstallationId;
    return DeviceResponse(deviceJwt: 'mock-device-jwt');
  }

  @override
  Future<void> updateDevice({String? deviceToken, String? defaultKid}) async {
    if (shouldFail) throw DeviceApiException('mock update failure');
    updateCalled = true;
    updateCallCount++;
    lastUpdateDeviceToken = deviceToken;
  }

  @override
  Future<void> deleteDevice() async {
    if (deleteShouldFail) throw DeviceApiException('mock delete failure');
    deleteCalled = true;
  }

  @override
  Future<DeviceRefreshResponse> refreshDeviceJwt({
    required String currentDeviceJwt,
  }) async {
    if (shouldFail) throw DeviceApiException('mock refresh failure');
    refreshJwtCalled = true;
    return DeviceRefreshResponse(deviceJwt: 'refreshed-jwt');
  }
}
