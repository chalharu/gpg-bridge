import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/http/api_exception.dart';
import 'package:gpg_bridge_mobile/http/error_interceptor.dart';
import 'package:gpg_bridge_mobile/http/token_refresh_interceptor.dart';

void main() {
  group('TokenRefreshInterceptor', () {
    late Dio dio;
    late int refreshCallCount;

    setUp(() {
      refreshCallCount = 0;
      dio = Dio(BaseOptions(baseUrl: 'https://api.example.com'));
    });

    test('triggers refresh on 401 and retries on success', () async {
      refreshCallCount = 0;

      // Set up a mock adapter that returns 401 on first call, 200 on second.
      var callCount = 0;
      dio.httpClientAdapter = _MockAdapter((options, _, _) async {
        callCount++;
        if (callCount == 1) {
          return ResponseBody.fromString(
            '{"error":"unauthorized"}',
            401,
            headers: {
              'content-type': ['application/json'],
            },
          );
        }
        return ResponseBody.fromString(
          '{"ok":true}',
          200,
          headers: {
            'content-type': ['application/json'],
          },
        );
      });

      dio.interceptors.addAll([
        ErrorInterceptor(),
        TokenRefreshInterceptor(
          dio: dio,
          tokenRefresher: () async {
            refreshCallCount++;
            return true;
          },
        ),
      ]);

      final response = await dio.get<dynamic>('/test');

      expect(response.statusCode, 200);
      expect(refreshCallCount, 1);
      expect(callCount, 2);
    });

    test('propagates error when refresh fails', () async {
      dio.httpClientAdapter = _MockAdapter((options, _, _) async {
        return ResponseBody.fromString(
          '{"error":"unauthorized"}',
          401,
          headers: {
            'content-type': ['application/json'],
          },
        );
      });

      dio.interceptors.addAll([
        ErrorInterceptor(),
        TokenRefreshInterceptor(dio: dio, tokenRefresher: () async => false),
      ]);

      expect(() => dio.get<dynamic>('/test'), throwsA(isA<ApiException>()));
    });

    test('does not retry refresh endpoint itself', () async {
      refreshCallCount = 0;

      dio.httpClientAdapter = _MockAdapter((options, _, _) async {
        return ResponseBody.fromString(
          '{"error":"unauthorized"}',
          401,
          headers: {
            'content-type': ['application/json'],
          },
        );
      });

      dio.interceptors.addAll([
        ErrorInterceptor(),
        TokenRefreshInterceptor(
          dio: dio,
          tokenRefresher: () async {
            refreshCallCount++;
            return true;
          },
        ),
      ]);

      expect(
        () => dio.post<dynamic>('/device/refresh'),
        throwsA(isA<ApiException>()),
      );
      expect(refreshCallCount, 0);
    });

    test('does not intercept non-401 errors', () async {
      refreshCallCount = 0;

      dio.httpClientAdapter = _MockAdapter((options, _, _) async {
        return ResponseBody.fromString(
          '{"error":"forbidden"}',
          403,
          headers: {
            'content-type': ['application/json'],
          },
        );
      });

      dio.interceptors.addAll([
        ErrorInterceptor(),
        TokenRefreshInterceptor(
          dio: dio,
          tokenRefresher: () async {
            refreshCallCount++;
            return true;
          },
        ),
      ]);

      expect(() => dio.get<dynamic>('/test'), throwsA(isA<ApiException>()));
      expect(refreshCallCount, 0);
    });

    test('coalesces concurrent 401 requests into a single refresh', () async {
      refreshCallCount = 0;
      var adapterCallCount = 0;

      dio.httpClientAdapter = _MockAdapter((options, _, _) async {
        adapterCallCount++;
        // First two calls return 401, subsequent calls return 200
        if (adapterCallCount <= 2) {
          return ResponseBody.fromString(
            '{"error":"unauthorized"}',
            401,
            headers: {
              'content-type': ['application/json'],
            },
          );
        }
        return ResponseBody.fromString(
          '{"ok":true}',
          200,
          headers: {
            'content-type': ['application/json'],
          },
        );
      });

      dio.interceptors.addAll([
        ErrorInterceptor(),
        TokenRefreshInterceptor(
          dio: dio,
          tokenRefresher: () async {
            refreshCallCount++;
            // Simulate async delay for the refresh
            await Future<void>.delayed(const Duration(milliseconds: 10));
            return true;
          },
        ),
      ]);

      // Fire two concurrent requests that both get 401
      final results = await Future.wait([
        dio.get<dynamic>('/test1'),
        dio.get<dynamic>('/test2'),
      ]);

      expect(results[0].statusCode, 200);
      expect(results[1].statusCode, 200);
      // tokenRefresher should be called exactly once
      expect(refreshCallCount, 1);
    });

    test('propagates exception to all waiters when refresher throws', () async {
      refreshCallCount = 0;

      dio.httpClientAdapter = _MockAdapter((options, _, _) async {
        return ResponseBody.fromString(
          '{"error":"unauthorized"}',
          401,
          headers: {
            'content-type': ['application/json'],
          },
        );
      });

      dio.interceptors.addAll([
        ErrorInterceptor(),
        TokenRefreshInterceptor(
          dio: dio,
          tokenRefresher: () async {
            refreshCallCount++;
            await Future<void>.delayed(const Duration(milliseconds: 10));
            throw Exception('refresh service unavailable');
          },
        ),
      ]);

      // Fire two concurrent requests that both get 401
      final errors = <Object>[];
      Future<void> capture(Future<dynamic> f) async {
        try {
          await f;
        } catch (e) {
          errors.add(e);
        }
      }

      await Future.wait([
        capture(dio.get<dynamic>('/test1')),
        capture(dio.get<dynamic>('/test2')),
      ]);

      // Both should fail with an error about token refresh
      expect(errors, hasLength(2));
      for (final error in errors) {
        expect(error, isA<DioException>());
        expect(
          (error as DioException).message,
          contains('token refresh failed'),
        );
      }

      // tokenRefresher should be called exactly once even with concurrent 401s
      expect(refreshCallCount, 1);
    });
  });
}

/// Simple mock HTTP adapter for Dio.
class _MockAdapter implements HttpClientAdapter {
  _MockAdapter(this._handler);

  final Future<ResponseBody> Function(
    RequestOptions options,
    Stream<List<int>>? requestStream,
    Future<void>? cancelFuture,
  )
  _handler;

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<List<int>>? requestStream,
    Future<void>? cancelFuture,
  ) {
    return _handler(options, requestStream, cancelFuture);
  }

  @override
  void close({bool force = false}) {}
}
