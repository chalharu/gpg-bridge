import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/http/api_config.dart';
import 'package:gpg_bridge_mobile/http/auth_interceptor.dart';
import 'package:gpg_bridge_mobile/http/debug_log_interceptor.dart';
import 'package:gpg_bridge_mobile/http/device_api_service.dart';
import 'package:gpg_bridge_mobile/http/error_interceptor.dart';
import 'package:gpg_bridge_mobile/http/http_client_provider.dart';
import 'package:gpg_bridge_mobile/http/token_refresh_interceptor.dart';
import 'package:gpg_bridge_mobile/security/device_assertion_jwt_service.dart';
import 'package:gpg_bridge_mobile/security/secure_storage_service.dart';

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

      // Dio adds ImplyContentTypeInterceptor by default, plus our 4.
      expect(interceptors.length, 5);
      expect(interceptors[1], isA<DebugLogInterceptor>());
      expect(interceptors[2], isA<AuthInterceptor>());
      expect(interceptors[3], isA<ErrorInterceptor>());
      expect(interceptors[4], isA<TokenRefreshInterceptor>());
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
