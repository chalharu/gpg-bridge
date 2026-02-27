import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/http/api_config.dart';
import 'package:gpg_bridge_mobile/http/api_exception.dart';
import 'package:gpg_bridge_mobile/http/auth_interceptor.dart';
import 'package:gpg_bridge_mobile/http/debug_log_interceptor.dart';
import 'package:gpg_bridge_mobile/http/device_api_service.dart';
import 'package:gpg_bridge_mobile/http/device_jwt_refresh_interceptor.dart';
import 'package:gpg_bridge_mobile/http/error_interceptor.dart';
import 'package:gpg_bridge_mobile/http/http_client_provider.dart';
import 'package:gpg_bridge_mobile/http/token_refresh_interceptor.dart';
import 'package:gpg_bridge_mobile/security/device_assertion_jwt_service.dart';
import 'package:gpg_bridge_mobile/security/secure_storage_service.dart';
import 'package:gpg_bridge_mobile/state/auth_state.dart';

import 'helpers/in_memory_secure_storage_backend.dart';

void main() {
  group('httpClientProvider', () {
    late ProviderContainer container;

    setUp(() {
      container = ProviderContainer(
        overrides: [
          secureStorageProvider.overrideWithValue(
            SecureStorageService(InMemorySecureStorageBackend()),
          ),
          deviceAssertionJwtProvider.overrideWithValue(
            _StubDeviceAssertionJwtService(),
          ),
          deviceApiProvider.overrideWithValue(_StubDeviceApiService()),
        ],
      );
    });

    tearDown(() => container.dispose());

    test('creates Dio with correct base configuration', () {
      final dio = container.read(httpClientProvider);

      expect(dio.options.baseUrl, ApiConfig.baseUrl);
      expect(dio.options.connectTimeout, ApiConfig.connectTimeout);
      expect(dio.options.receiveTimeout, ApiConfig.receiveTimeout);
      expect(dio.options.sendTimeout, ApiConfig.sendTimeout);
      expect(dio.options.contentType, 'application/json');
    });

    test('attaches interceptors in correct order', () {
      final dio = container.read(httpClientProvider);
      final interceptors = dio.interceptors;

      // Dio adds ImplyContentTypeInterceptor by default, plus our 5.
      expect(interceptors.length, 6);
      expect(interceptors[1], isA<DebugLogInterceptor>());
      expect(interceptors[2], isA<DeviceJwtRefreshInterceptor>());
      expect(interceptors[3], isA<AuthInterceptor>());
      expect(interceptors[4], isA<ErrorInterceptor>());
      expect(interceptors[5], isA<TokenRefreshInterceptor>());
    });

    test('tokenProvider returns null when no device_id stored', () async {
      final tokenProvider = container.read(tokenProviderProvider);
      final token = await tokenProvider(RequestOptions(path: '/test'));
      expect(token, isNull);
    });

    test('tokenRefresher returns false when no device_jwt stored', () async {
      final tokenRefresher = container.read(tokenRefresherProvider);
      final result = await tokenRefresher();
      expect(result, isFalse);
    });
  });

  group('tokenRefresherProvider', () {
    test('returns true and stores JWT on successful refresh', () async {
      final backend = InMemorySecureStorageBackend();
      final storage = SecureStorageService(backend);
      await storage.writeValue(
        key: SecureStorageKeys.deviceJwt,
        value: 'old-jwt',
      );

      final container = ProviderContainer(
        overrides: [
          secureStorageProvider.overrideWith((ref) => storage),
          deviceApiProvider.overrideWith((ref) => _SuccessDeviceApiService()),
        ],
      );
      addTearDown(container.dispose);

      // Initialize authState so the notifier is available.
      await container.read(authStateProvider.future);

      final refresher = container.read(tokenRefresherProvider);
      final result = await refresher();

      expect(result, isTrue);
      expect(
        await storage.readValue(key: SecureStorageKeys.deviceJwt),
        'new-jwt',
      );
    });

    test('returns false and clears auth on 401 ApiException', () async {
      final backend = InMemorySecureStorageBackend();
      final storage = SecureStorageService(backend);
      await storage.writeValue(
        key: SecureStorageKeys.deviceJwt,
        value: 'old-jwt',
      );

      final container = ProviderContainer(
        overrides: [
          secureStorageProvider.overrideWith((ref) => storage),
          deviceApiProvider.overrideWith(
            (ref) => _Failing401DeviceApiService(),
          ),
        ],
      );
      addTearDown(container.dispose);

      await container.read(authStateProvider.future);

      final refresher = container.read(tokenRefresherProvider);
      final result = await refresher();

      expect(result, isFalse);
      // deviceJwt should be deleted.
      expect(await storage.readValue(key: SecureStorageKeys.deviceJwt), isNull);
      // auth state should be false.
      final authState = await container.read(authStateProvider.future);
      expect(authState, isFalse);
    });

    test('returns false but does NOT clear auth on non-401 error', () async {
      final backend = InMemorySecureStorageBackend();
      final storage = SecureStorageService(backend);
      await storage.writeValue(
        key: SecureStorageKeys.deviceJwt,
        value: 'old-jwt',
      );

      final container = ProviderContainer(
        overrides: [
          secureStorageProvider.overrideWith((ref) => storage),
          deviceApiProvider.overrideWith(
            (ref) => _FailingNetworkDeviceApiService(),
          ),
        ],
      );
      addTearDown(container.dispose);

      await container.read(authStateProvider.future);

      final refresher = container.read(tokenRefresherProvider);
      final result = await refresher();

      expect(result, isFalse);
      // deviceJwt should NOT be deleted (non-401 error).
      expect(
        await storage.readValue(key: SecureStorageKeys.deviceJwt),
        'old-jwt',
      );
      // auth state should still be true (JWT is still in storage).
      final authState = await container.read(authStateProvider.future);
      expect(authState, isTrue);
    });

    test('returns false and clears auth when no JWT stored', () async {
      final backend = InMemorySecureStorageBackend();
      final storage = SecureStorageService(backend);

      final container = ProviderContainer(
        overrides: [
          secureStorageProvider.overrideWith((ref) => storage),
          deviceApiProvider.overrideWith((ref) => _SuccessDeviceApiService()),
        ],
      );
      addTearDown(container.dispose);

      await container.read(authStateProvider.future);

      final refresher = container.read(tokenRefresherProvider);
      final result = await refresher();

      expect(result, isFalse);
      // auth state should be false.
      final authState = await container.read(authStateProvider.future);
      expect(authState, isFalse);
    });
  });
}

class _StubDeviceAssertionJwtService implements DeviceAssertionJwtService {
  @override
  Future<String> generate({
    required String firebaseInstallationId,
    required String audience,
    required String kid,
  }) async {
    return 'stub-jwt';
  }
}

class _StubDeviceApiService implements DeviceApiService {
  @override
  Future<DeviceResponse> registerDevice({
    required String deviceToken,
    required String firebaseInstallationId,
    required List<Map<String, dynamic>> sigKeys,
    required List<Map<String, dynamic>> encKeys,
    String? defaultKid,
  }) async {
    return DeviceResponse(deviceJwt: 'stub-jwt');
  }

  @override
  Future<void> updateDevice({String? deviceToken, String? defaultKid}) async {}

  @override
  Future<void> deleteDevice() async {}

  @override
  Future<DeviceRefreshResponse> refreshDeviceJwt({
    required String currentDeviceJwt,
  }) async {
    return DeviceRefreshResponse(deviceJwt: 'refreshed-stub');
  }
}

class _SuccessDeviceApiService implements DeviceApiService {
  @override
  Future<DeviceResponse> registerDevice({
    required String deviceToken,
    required String firebaseInstallationId,
    required List<Map<String, dynamic>> sigKeys,
    required List<Map<String, dynamic>> encKeys,
    String? defaultKid,
  }) async {
    throw UnsupportedError('not used in this test');
  }

  @override
  Future<void> updateDevice({String? deviceToken, String? defaultKid}) async {
    throw UnsupportedError('not used in this test');
  }

  @override
  Future<void> deleteDevice() async {
    throw UnsupportedError('not used in this test');
  }

  @override
  Future<DeviceRefreshResponse> refreshDeviceJwt({
    required String currentDeviceJwt,
  }) async {
    return DeviceRefreshResponse(deviceJwt: 'new-jwt');
  }
}

class _Failing401DeviceApiService implements DeviceApiService {
  @override
  Future<DeviceResponse> registerDevice({
    required String deviceToken,
    required String firebaseInstallationId,
    required List<Map<String, dynamic>> sigKeys,
    required List<Map<String, dynamic>> encKeys,
    String? defaultKid,
  }) async {
    throw UnsupportedError('not used in this test');
  }

  @override
  Future<void> updateDevice({String? deviceToken, String? defaultKid}) async {
    throw UnsupportedError('not used in this test');
  }

  @override
  Future<void> deleteDevice() async {
    throw UnsupportedError('not used in this test');
  }

  @override
  Future<DeviceRefreshResponse> refreshDeviceJwt({
    required String currentDeviceJwt,
  }) async {
    throw ApiException(
      requestOptions: RequestOptions(path: '/device/refresh'),
      response: Response(
        requestOptions: RequestOptions(path: '/device/refresh'),
        statusCode: 401,
      ),
    );
  }
}

class _FailingNetworkDeviceApiService implements DeviceApiService {
  @override
  Future<DeviceResponse> registerDevice({
    required String deviceToken,
    required String firebaseInstallationId,
    required List<Map<String, dynamic>> sigKeys,
    required List<Map<String, dynamic>> encKeys,
    String? defaultKid,
  }) async {
    throw UnsupportedError('not used in this test');
  }

  @override
  Future<void> updateDevice({String? deviceToken, String? defaultKid}) async {
    throw UnsupportedError('not used in this test');
  }

  @override
  Future<void> deleteDevice() async {
    throw UnsupportedError('not used in this test');
  }

  @override
  Future<DeviceRefreshResponse> refreshDeviceJwt({
    required String currentDeviceJwt,
  }) async {
    throw Exception('network error');
  }
}
