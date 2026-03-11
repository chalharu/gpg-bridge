import 'package:dio/dio.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';

import '../security/device_assertion_jwt_service.dart';
import '../security/secure_storage_service.dart';
import '../state/auth_state.dart';
import 'api_config.dart';
import 'api_exception.dart';
import 'auth_interceptor.dart';
import 'debug_log_interceptor.dart';
import 'device_api_service.dart';
import 'device_jwt_refresh_interceptor.dart';
import 'error_interceptor.dart';
import 'server_url_interceptor.dart';
import 'server_url_service.dart';
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
  final serverUrlService = ref.read(serverUrlServiceProvider);

  return (RequestOptions options) async {
    final deviceId = await storageService.readValue(
      key: SecureStorageKeys.deviceId,
    );
    if (deviceId == null || deviceId.isEmpty) return null;

    final sigKid = await storageService.readValue(
      key: SecureStorageKeys.sigKid,
    );
    if (sigKid == null || sigKid.isEmpty) return null;

    final overrideUrl = options.extra[serverUrlOverrideExtraKey] as String?;
    final baseUrl = overrideUrl ?? await serverUrlService.getSavedOrDefault();
    final audience = _resolveAudience(
      serverUrlService: serverUrlService,
      baseUrl: baseUrl,
      path: options.path,
    );

    return jwtService.generate(
      firebaseInstallationId: deviceId,
      audience: audience,
      kid: sigKid,
    );
  };
}

String _resolveAudience({
  required ServerUrlService serverUrlService,
  required String baseUrl,
  required String path,
}) {
  if (path.startsWith('http://') || path.startsWith('https://')) {
    return path;
  }
  return serverUrlService.buildEndpointUrl(baseUrl: baseUrl, path: path);
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
    if (currentJwt == null || currentJwt.isEmpty) {
      await _clearAuthState(ref, storageService);
      return false;
    }

    try {
      final response = await deviceApiService.refreshDeviceJwt(
        currentDeviceJwt: currentJwt,
      );
      await storageService.writeValue(
        key: SecureStorageKeys.deviceJwt,
        value: response.deviceJwt,
      );
      return true;
    } on ApiException catch (e) {
      if (e.response?.statusCode == 401) {
        await _clearAuthState(ref, storageService);
      }
      return false;
    } catch (_) {
      return false;
    }
  };
}

Future<void> _clearAuthState(Ref ref, SecureStorageService storage) async {
  await storage.deleteValue(key: SecureStorageKeys.deviceJwt);
  await ref.read(authStateProvider.notifier).setRegistered(false);
}

/// Creates and configures the [Dio] HTTP client with all interceptors.
///
/// Interceptor order:
/// 1. [ServerUrlInterceptor] – resolves the runtime-selected server URL
/// 2. [DebugLogInterceptor] – logs requests/responses in debug builds
/// 3. [DeviceJwtRefreshInterceptor] – proactively refreshes device_jwt
/// 4. [AuthInterceptor] – attaches `Authorization: Bearer` header
/// 5. [ErrorInterceptor] – parses error responses into [ApiException]
/// 6. [TokenRefreshInterceptor] – retries on 401 after device_jwt refresh
@Riverpod(keepAlive: true)
Dio httpClient(Ref ref) {
  final serverUrlService = ref.read(serverUrlServiceProvider);
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
    ServerUrlInterceptor(serverUrlService: serverUrlService),
    DebugLogInterceptor(),
    DeviceJwtRefreshInterceptor(
      jwtReader: () => ref
          .read(secureStorageProvider)
          .readValue(key: SecureStorageKeys.deviceJwt),
      refreshCallback: () async {
        await ref.read(tokenRefresherProvider)();
      },
    ),
    AuthInterceptor(tokenProvider: ref.watch(tokenProviderProvider)),
    ErrorInterceptor(),
    TokenRefreshInterceptor(
      dio: dio,
      tokenRefresher: ref.watch(tokenRefresherProvider),
    ),
  ]);

  return dio;
}
