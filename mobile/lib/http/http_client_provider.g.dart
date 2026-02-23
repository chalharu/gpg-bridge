// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'http_client_provider.dart';

// **************************************************************************
// RiverpodGenerator
// **************************************************************************

// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint, type=warning
/// Provides a callback to generate a device_assertion_jwt.
///
/// Override this provider to supply the actual JWT generation logic
/// (e.g. signing with the device private key from Keystore / Secure Enclave).

@ProviderFor(tokenProvider)
const tokenProviderProvider = TokenProviderProvider._();

/// Provides a callback to generate a device_assertion_jwt.
///
/// Override this provider to supply the actual JWT generation logic
/// (e.g. signing with the device private key from Keystore / Secure Enclave).

final class TokenProviderProvider
    extends $FunctionalProvider<TokenProvider, TokenProvider, TokenProvider>
    with $Provider<TokenProvider> {
  /// Provides a callback to generate a device_assertion_jwt.
  ///
  /// Override this provider to supply the actual JWT generation logic
  /// (e.g. signing with the device private key from Keystore / Secure Enclave).
  const TokenProviderProvider._()
    : super(
        from: null,
        argument: null,
        retry: null,
        name: r'tokenProviderProvider',
        isAutoDispose: true,
        dependencies: null,
        $allTransitiveDependencies: null,
      );

  @override
  String debugGetCreateSourceHash() => _$tokenProviderHash();

  @$internal
  @override
  $ProviderElement<TokenProvider> $createElement($ProviderPointer pointer) =>
      $ProviderElement(pointer);

  @override
  TokenProvider create(Ref ref) {
    return tokenProvider(ref);
  }

  /// {@macro riverpod.override_with_value}
  Override overrideWithValue(TokenProvider value) {
    return $ProviderOverride(
      origin: this,
      providerOverride: $SyncValueProvider<TokenProvider>(value),
    );
  }
}

String _$tokenProviderHash() => r'4c650446be89070259c7c73a00fea157d9706dc0';

/// Provides a callback to refresh the device_jwt via POST /device/refresh.
///
/// Override this provider to supply the actual refresh logic.

@ProviderFor(tokenRefresher)
const tokenRefresherProvider = TokenRefresherProvider._();

/// Provides a callback to refresh the device_jwt via POST /device/refresh.
///
/// Override this provider to supply the actual refresh logic.

final class TokenRefresherProvider
    extends $FunctionalProvider<TokenRefresher, TokenRefresher, TokenRefresher>
    with $Provider<TokenRefresher> {
  /// Provides a callback to refresh the device_jwt via POST /device/refresh.
  ///
  /// Override this provider to supply the actual refresh logic.
  const TokenRefresherProvider._()
    : super(
        from: null,
        argument: null,
        retry: null,
        name: r'tokenRefresherProvider',
        isAutoDispose: true,
        dependencies: null,
        $allTransitiveDependencies: null,
      );

  @override
  String debugGetCreateSourceHash() => _$tokenRefresherHash();

  @$internal
  @override
  $ProviderElement<TokenRefresher> $createElement($ProviderPointer pointer) =>
      $ProviderElement(pointer);

  @override
  TokenRefresher create(Ref ref) {
    return tokenRefresher(ref);
  }

  /// {@macro riverpod.override_with_value}
  Override overrideWithValue(TokenRefresher value) {
    return $ProviderOverride(
      origin: this,
      providerOverride: $SyncValueProvider<TokenRefresher>(value),
    );
  }
}

String _$tokenRefresherHash() => r'0a1cf6ef0c16bdd683265f2a275a99e900636394';

/// Creates and configures the [Dio] HTTP client with all interceptors.
///
/// Interceptor order:
/// 1. [DebugLogInterceptor] – logs requests/responses in debug builds
/// 2. [AuthInterceptor] – attaches `Authorization: Bearer` header
/// 3. [ErrorInterceptor] – parses error responses into [ApiException]
/// 4. [TokenRefreshInterceptor] – retries on 401 after device_jwt refresh

@ProviderFor(httpClient)
const httpClientProvider = HttpClientProvider._();

/// Creates and configures the [Dio] HTTP client with all interceptors.
///
/// Interceptor order:
/// 1. [DebugLogInterceptor] – logs requests/responses in debug builds
/// 2. [AuthInterceptor] – attaches `Authorization: Bearer` header
/// 3. [ErrorInterceptor] – parses error responses into [ApiException]
/// 4. [TokenRefreshInterceptor] – retries on 401 after device_jwt refresh

final class HttpClientProvider extends $FunctionalProvider<Dio, Dio, Dio>
    with $Provider<Dio> {
  /// Creates and configures the [Dio] HTTP client with all interceptors.
  ///
  /// Interceptor order:
  /// 1. [DebugLogInterceptor] – logs requests/responses in debug builds
  /// 2. [AuthInterceptor] – attaches `Authorization: Bearer` header
  /// 3. [ErrorInterceptor] – parses error responses into [ApiException]
  /// 4. [TokenRefreshInterceptor] – retries on 401 after device_jwt refresh
  const HttpClientProvider._()
    : super(
        from: null,
        argument: null,
        retry: null,
        name: r'httpClientProvider',
        isAutoDispose: true,
        dependencies: null,
        $allTransitiveDependencies: null,
      );

  @override
  String debugGetCreateSourceHash() => _$httpClientHash();

  @$internal
  @override
  $ProviderElement<Dio> $createElement($ProviderPointer pointer) =>
      $ProviderElement(pointer);

  @override
  Dio create(Ref ref) {
    return httpClient(ref);
  }

  /// {@macro riverpod.override_with_value}
  Override overrideWithValue(Dio value) {
    return $ProviderOverride(
      origin: this,
      providerOverride: $SyncValueProvider<Dio>(value),
    );
  }
}

String _$httpClientHash() => r'd2d2e2342fc8ea690cdef484a0817b430ff1e9f6';
