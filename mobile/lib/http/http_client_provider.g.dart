// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'http_client_provider.dart';

// **************************************************************************
// RiverpodGenerator
// **************************************************************************

// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint, type=warning
/// Provides a callback to generate a device_assertion_jwt.
///
/// Generates a fresh ES256-signed JWT for each API call using the device
/// private key from Keystore / Secure Enclave.

@ProviderFor(tokenProvider)
const tokenProviderProvider = TokenProviderProvider._();

/// Provides a callback to generate a device_assertion_jwt.
///
/// Generates a fresh ES256-signed JWT for each API call using the device
/// private key from Keystore / Secure Enclave.

final class TokenProviderProvider
    extends $FunctionalProvider<TokenProvider, TokenProvider, TokenProvider>
    with $Provider<TokenProvider> {
  /// Provides a callback to generate a device_assertion_jwt.
  ///
  /// Generates a fresh ES256-signed JWT for each API call using the device
  /// private key from Keystore / Secure Enclave.
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

String _$tokenProviderHash() => r'446fffe8031366b86491092e1a18b95953547a1b';

/// Provides a callback to refresh the device_jwt via POST /device/refresh.
///
/// Reads the current device_jwt from secure storage, calls the refresh
/// endpoint, and stores the new JWT.
///
/// Providers are read lazily inside the closure to avoid a circular
/// dependency with [httpClientProvider] → [deviceApiProvider].

@ProviderFor(tokenRefresher)
const tokenRefresherProvider = TokenRefresherProvider._();

/// Provides a callback to refresh the device_jwt via POST /device/refresh.
///
/// Reads the current device_jwt from secure storage, calls the refresh
/// endpoint, and stores the new JWT.
///
/// Providers are read lazily inside the closure to avoid a circular
/// dependency with [httpClientProvider] → [deviceApiProvider].

final class TokenRefresherProvider
    extends $FunctionalProvider<TokenRefresher, TokenRefresher, TokenRefresher>
    with $Provider<TokenRefresher> {
  /// Provides a callback to refresh the device_jwt via POST /device/refresh.
  ///
  /// Reads the current device_jwt from secure storage, calls the refresh
  /// endpoint, and stores the new JWT.
  ///
  /// Providers are read lazily inside the closure to avoid a circular
  /// dependency with [httpClientProvider] → [deviceApiProvider].
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

String _$tokenRefresherHash() => r'616900f81f95507ae5ea93ca47f2ed23d639090b';

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
        isAutoDispose: false,
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

String _$httpClientHash() => r'55015cf5a7e64a80f505c6669da8bc20a46ffae1';
