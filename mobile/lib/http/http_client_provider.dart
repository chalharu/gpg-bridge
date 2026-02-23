import 'package:dio/dio.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';

import 'api_config.dart';
import 'auth_interceptor.dart';
import 'debug_log_interceptor.dart';
import 'error_interceptor.dart';
import 'token_refresh_interceptor.dart';

part 'http_client_provider.g.dart';

/// Provides a callback to generate a device_assertion_jwt.
///
/// Override this provider to supply the actual JWT generation logic
/// (e.g. signing with the device private key from Keystore / Secure Enclave).
@riverpod
TokenProvider tokenProvider(Ref ref) {
  return () async => null;
}

/// Provides a callback to refresh the device_jwt via POST /device/refresh.
///
/// Override this provider to supply the actual refresh logic.
@riverpod
TokenRefresher tokenRefresher(Ref ref) {
  return () async => false;
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
