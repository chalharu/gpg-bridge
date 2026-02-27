import 'package:dio/dio.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';

import '../security/device_assertion_jwt_service.dart';
import '../security/secure_storage_service.dart';
import 'api_config.dart';
import 'auth_interceptor.dart';
import 'debug_log_interceptor.dart';
import 'device_api_service.dart';
import 'error_interceptor.dart';
import 'token_refresh_interceptor.dart';

part 'http_client_provider.g.dart';

/// Provides a callback to generate a device_assertion_jwt.
///
/// Generates a fresh ES256-signed JWT for each API call using the device
/// private key from Keystore / Secure Enclave.
@riverpod
TokenProvider tokenProvider(Ref ref) {
  final jwtService = ref.read(deviceAssertionJwtProvider);
  final storageService = ref.read(secureStorageProvider);

  return (RequestOptions options) async {
    final deviceId = await storageService.readValue(
      key: SecureStorageKeys.deviceId,
    );
    if (deviceId == null || deviceId.isEmpty) return null;

    final sigKid = await storageService.readValue(
      key: SecureStorageKeys.sigKid,
    );
    if (sigKid == null || sigKid.isEmpty) return null;

    return jwtService.generate(
      firebaseInstallationId: deviceId,
      audience: '${ApiConfig.baseUrl}${options.path}',
      kid: sigKid,
    );
  };
}

/// Provides a callback to refresh the device_jwt via POST /device/refresh.
///
/// Reads the current device_jwt from secure storage, calls the refresh
/// endpoint, and stores the new JWT.
///
/// Providers are read lazily inside the closure to avoid a circular
/// dependency with [httpClientProvider] → [deviceApiProvider].
@riverpod
TokenRefresher tokenRefresher(Ref ref) {
  return () async {
    final storageService = ref.read(secureStorageProvider);
    final deviceApiService = ref.read(deviceApiProvider);

    final currentJwt = await storageService.readValue(
      key: SecureStorageKeys.deviceJwt,
    );
    if (currentJwt == null || currentJwt.isEmpty) return false;

    try {
      final response = await deviceApiService.refreshDeviceJwt(
        currentDeviceJwt: currentJwt,
      );
      await storageService.writeValue(
        key: SecureStorageKeys.deviceJwt,
        value: response.deviceJwt,
      );
      return true;
    } catch (_) {
      return false;
    }
  };
}

/// Creates and configures the [Dio] HTTP client with all interceptors.
///
/// Interceptor order:
/// 1. [DebugLogInterceptor] – logs requests/responses in debug builds
/// 2. [AuthInterceptor] – attaches `Authorization: Bearer` header
/// 3. [ErrorInterceptor] – parses error responses into [ApiException]
/// 4. [TokenRefreshInterceptor] – retries on 401 after device_jwt refresh
@Riverpod(keepAlive: true)
Dio httpClient(Ref ref) {
  final dio = Dio(
    BaseOptions(
      baseUrl: ApiConfig.baseUrl,
      connectTimeout: ApiConfig.connectTimeout,
      receiveTimeout: ApiConfig.receiveTimeout,
      sendTimeout: ApiConfig.sendTimeout,
      contentType: 'application/json',
      responseType: ResponseType.json,
    ),
  );

  dio.interceptors.addAll([
    DebugLogInterceptor(),
    AuthInterceptor(tokenProvider: ref.watch(tokenProviderProvider)),
    ErrorInterceptor(),
    TokenRefreshInterceptor(
      dio: dio,
      tokenRefresher: ref.watch(tokenRefresherProvider),
    ),
  ]);

  return dio;
}
