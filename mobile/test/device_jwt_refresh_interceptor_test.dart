import 'dart:async';
import 'dart:convert';

import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/http/auth_interceptor.dart';
import 'package:gpg_bridge_mobile/http/device_jwt_refresh_interceptor.dart';

void main() {
  group('DeviceJwtRefreshInterceptor', () {
    late Dio dio;
    late int refreshCallCount;
    late String? storedJwt;

    setUp(() {
      refreshCallCount = 0;
      storedJwt = null;
      dio = Dio(BaseOptions(baseUrl: 'https://api.example.com'));
    });

    /// Builds a fake JWT with the given iat/exp timestamps.
    String buildJwt({required int iat, required int exp}) {
      final header = base64Url
          .encode(utf8.encode('{"alg":"ES256","typ":"JWT"}'))
          .replaceAll('=', '');
      final payload = base64Url
          .encode(utf8.encode('{"iat":$iat,"exp":$exp,"sub":"test"}'))
          .replaceAll('=', '');
      return '$header.$payload.fake-sig';
    }

    void setupDio({JwtReader? jwtReader, RefreshCallback? refreshCallback}) {
      dio.httpClientAdapter = _MockAdapter((options, _, _) async {
        return ResponseBody.fromString(
          '{"ok":true}',
          200,
          headers: {
            'content-type': ['application/json'],
          },
        );
      });

      dio.interceptors.add(
        DeviceJwtRefreshInterceptor(
          jwtReader: jwtReader ?? () async => storedJwt,
          refreshCallback:
              refreshCallback ??
              () async {
                refreshCallCount++;
              },
        ),
      );
    }

    test('calls refresh when JWT needs refreshing', () async {
      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      storedJwt = buildJwt(iat: now - 7100, exp: now + 100);
      setupDio();

      final response = await dio.get<dynamic>('/test');

      expect(response.statusCode, 200);
      expect(refreshCallCount, 1);
    });

    test('does not call refresh when JWT is still fresh', () async {
      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      storedJwt = buildJwt(iat: now - 1200, exp: now + 6000);
      setupDio();

      final response = await dio.get<dynamic>('/test');

      expect(response.statusCode, 200);
      expect(refreshCallCount, 0);
    });

    test('skips auth-skipped requests', () async {
      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      storedJwt = buildJwt(iat: now - 7100, exp: now + 100);
      setupDio();

      final response = await dio.get<dynamic>(
        '/test',
        options: Options(extra: {skipAuthExtraKey: true}),
      );

      expect(response.statusCode, 200);
      expect(refreshCallCount, 0);
    });

    test('skips /device/refresh endpoint', () async {
      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      storedJwt = buildJwt(iat: now - 7100, exp: now + 100);
      setupDio();

      final response = await dio.post<dynamic>('/device/refresh');

      expect(response.statusCode, 200);
      expect(refreshCallCount, 0);
    });

    test('coalesces concurrent refresh calls', () async {
      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      storedJwt = buildJwt(iat: now - 7100, exp: now + 100);
      setupDio(
        refreshCallback: () async {
          refreshCallCount++;
          await Future<void>.delayed(const Duration(milliseconds: 20));
        },
      );

      final results = await Future.wait([
        dio.get<dynamic>('/test1'),
        dio.get<dynamic>('/test2'),
      ]);

      expect(results[0].statusCode, 200);
      expect(results[1].statusCode, 200);
      expect(refreshCallCount, 1);
    });

    test('proceeds with request even if refresh fails', () async {
      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      storedJwt = buildJwt(iat: now - 7100, exp: now + 100);
      setupDio(
        refreshCallback: () async {
          refreshCallCount++;
          throw Exception('refresh failed');
        },
      );

      final response = await dio.get<dynamic>('/test');

      expect(response.statusCode, 200);
      expect(refreshCallCount, 1);
    });

    test('proceeds with request when no JWT stored (null)', () async {
      storedJwt = null;
      setupDio();

      final response = await dio.get<dynamic>('/test');

      expect(response.statusCode, 200);
      expect(refreshCallCount, 0);
    });

    test('proceeds with request when JWT is empty string', () async {
      storedJwt = '';
      setupDio();

      final response = await dio.get<dynamic>('/test');

      expect(response.statusCode, 200);
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
