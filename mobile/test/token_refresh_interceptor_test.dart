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
