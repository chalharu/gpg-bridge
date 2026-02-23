import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/http/auth_interceptor.dart';

void main() {
  group('AuthInterceptor', () {
    test('adds Bearer header when token provider returns a token', () async {
      final interceptor = AuthInterceptor(
        tokenProvider: () async => 'test-jwt-token',
      );

      final options = RequestOptions(path: '/test');
      late RequestOptions captured;

      await interceptor.onRequest(
        options,
        _CaptureRequestHandler(onNext: (opts) => captured = opts),
      );

      expect(captured.headers['Authorization'], 'Bearer test-jwt-token');
    });

    test('does not add header when token provider returns null', () async {
      final interceptor = AuthInterceptor(tokenProvider: () async => null);

      final options = RequestOptions(path: '/test');
      late RequestOptions captured;

      await interceptor.onRequest(
        options,
        _CaptureRequestHandler(onNext: (opts) => captured = opts),
      );

      expect(captured.headers.containsKey('Authorization'), isFalse);
    });

    test(
      'does not add header when token provider returns empty string',
      () async {
        final interceptor = AuthInterceptor(tokenProvider: () async => '');

        final options = RequestOptions(path: '/test');
        late RequestOptions captured;

        await interceptor.onRequest(
          options,
          _CaptureRequestHandler(onNext: (opts) => captured = opts),
        );

        expect(captured.headers.containsKey('Authorization'), isFalse);
      },
    );

    test('rejects request when token provider throws', () async {
      final interceptor = AuthInterceptor(
        tokenProvider: () async => throw Exception('key store failure'),
      );

      final options = RequestOptions(path: '/test');
      DioException? rejectedError;

      await interceptor.onRequest(
        options,
        _CaptureRequestHandler(onReject: (err) => rejectedError = err),
      );

      expect(rejectedError, isNotNull);
      expect(rejectedError!.message, 'failed to generate auth token');
      expect(rejectedError!.error, isA<Exception>());
    });
  });
}

/// Minimal [RequestInterceptorHandler] that captures the result.
class _CaptureRequestHandler extends RequestInterceptorHandler {
  _CaptureRequestHandler({this.onNext, this.onReject});

  final void Function(RequestOptions)? onNext;
  final void Function(DioException)? onReject;

  @override
  void next(RequestOptions requestOptions) {
    onNext?.call(requestOptions);
  }

  @override
  void reject(
    DioException error, [
    bool callFollowingErrorInterceptor = false,
  ]) {
    onReject?.call(error);
  }

  @override
  void resolve(
    Response<dynamic> response, [
    bool callFollowingResponseInterceptor = false,
  ]) {}
}
