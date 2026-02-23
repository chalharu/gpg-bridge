import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/http/api_config.dart';
import 'package:gpg_bridge_mobile/http/auth_interceptor.dart';
import 'package:gpg_bridge_mobile/http/debug_log_interceptor.dart';
import 'package:gpg_bridge_mobile/http/error_interceptor.dart';
import 'package:gpg_bridge_mobile/http/http_client_provider.dart';
import 'package:gpg_bridge_mobile/http/token_refresh_interceptor.dart';

void main() {
  group('httpClientProvider', () {
    test('creates Dio with correct base configuration', () {
      final container = ProviderContainer();
      addTearDown(container.dispose);

      final dio = container.read(httpClientProvider);

      expect(dio.options.baseUrl, ApiConfig.baseUrl);
      expect(dio.options.connectTimeout, ApiConfig.connectTimeout);
      expect(dio.options.receiveTimeout, ApiConfig.receiveTimeout);
      expect(dio.options.sendTimeout, ApiConfig.sendTimeout);
      expect(dio.options.contentType, 'application/json');
    });

    test('attaches interceptors in correct order', () {
      final container = ProviderContainer();
      addTearDown(container.dispose);

      final dio = container.read(httpClientProvider);
      final interceptors = dio.interceptors;

      // Dio adds ImplyContentTypeInterceptor by default, plus our 4.
      expect(interceptors.length, 5);
      expect(interceptors[1], isA<DebugLogInterceptor>());
      expect(interceptors[2], isA<AuthInterceptor>());
      expect(interceptors[3], isA<ErrorInterceptor>());
      expect(interceptors[4], isA<TokenRefreshInterceptor>());
    });

    test('tokenProviderProvider defaults to returning null', () async {
      final container = ProviderContainer();
      addTearDown(container.dispose);

      final tokenProvider = container.read(tokenProviderProvider);
      final token = await tokenProvider();
      expect(token, isNull);
    });

    test('tokenRefresherProvider defaults to returning false', () async {
      final container = ProviderContainer();
      addTearDown(container.dispose);

      final tokenRefresher = container.read(tokenRefresherProvider);
      final result = await tokenRefresher();
      expect(result, isFalse);
    });
  });
}
