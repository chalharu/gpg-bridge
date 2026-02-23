import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/http/debug_log_interceptor.dart';

void main() {
  group('DebugLogInterceptor', () {
    late DebugLogInterceptor interceptor;

    setUp(() {
      interceptor = DebugLogInterceptor();
    });

    test('onRequest passes through to next handler', () {
      final options = RequestOptions(path: '/test');
      final handler = _CaptureRequestHandler();
      interceptor.onRequest(options, handler);
      expect(handler.nextOptions, isNotNull);
      expect(handler.nextOptions!.path, '/test');
    });

    test('onResponse passes response through', () {
      final requestOptions = RequestOptions(path: '/test');
      final response = Response<dynamic>(
        requestOptions: requestOptions,
        statusCode: 200,
        data: {'success': true},
      );

      final handler = _CaptureResponseHandler();
      interceptor.onResponse(response, handler);
      expect(handler.response, isNotNull);
      expect(handler.response!.statusCode, 200);
    });

    test('onError passes error through', () {
      final options = RequestOptions(path: '/test');
      final error = DioException(
        requestOptions: options,
        message: 'test error',
      );

      final handler = _CaptureErrorHandler();
      interceptor.onError(error, handler);
      expect(handler.error, isNotNull);
      expect(handler.error!.message, 'test error');
    });
  });
}

class _CaptureRequestHandler extends RequestInterceptorHandler {
  RequestOptions? nextOptions;

  @override
  void next(RequestOptions requestOptions) {
    nextOptions = requestOptions;
  }
}

class _CaptureResponseHandler extends ResponseInterceptorHandler {
  Response<dynamic>? response;

  @override
  void next(Response<dynamic> res) {
    response = res;
  }

  @override
  void resolve(Response<dynamic> res) {
    response = res;
  }
}

class _CaptureErrorHandler extends ErrorInterceptorHandler {
  DioException? error;

  @override
  void next(DioException err) {
    error = err;
  }
}
