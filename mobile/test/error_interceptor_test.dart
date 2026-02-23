import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/http/api_exception.dart';
import 'package:gpg_bridge_mobile/http/error_interceptor.dart';

void main() {
  late ErrorInterceptor interceptor;

  setUp(() {
    interceptor = ErrorInterceptor();
  });

  // ---------------------------------------------------------------------------
  // onResponse
  // ---------------------------------------------------------------------------

  group('onResponse', () {
    test('passes through successful responses', () {
      final response = Response<dynamic>(
        requestOptions: RequestOptions(path: '/test'),
        statusCode: 200,
        data: {'ok': true},
      );

      late Response<dynamic> captured;
      interceptor.onResponse(
        response,
        _CaptureResponseHandler(onNext: (r) => captured = r),
      );

      expect(captured.statusCode, 200);
    });

    test('rejects 4xx responses as ApiException', () {
      final response = Response<dynamic>(
        requestOptions: RequestOptions(path: '/test'),
        statusCode: 400,
        data: <String, dynamic>{'error': 'bad_request', 'message': 'Invalid'},
      );

      DioException? rejected;
      interceptor.onResponse(
        response,
        _CaptureResponseHandler(onReject: (e) => rejected = e),
      );

      expect(rejected, isA<ApiException>());
      final apiEx = rejected! as ApiException;
      expect(apiEx.errorResponse?.error, 'bad_request');
    });

    test('rejects 5xx responses as ApiException', () {
      final response = Response<dynamic>(
        requestOptions: RequestOptions(path: '/test'),
        statusCode: 500,
        data: <String, dynamic>{'error': 'internal', 'message': 'Oops'},
      );

      DioException? rejected;
      interceptor.onResponse(
        response,
        _CaptureResponseHandler(onReject: (e) => rejected = e),
      );

      expect(rejected, isA<ApiException>());
    });
  });

  // ---------------------------------------------------------------------------
  // onError – RFC 7807
  // ---------------------------------------------------------------------------

  group('onError – RFC 7807', () {
    test('parses application/problem+json as ProblemDetails', () {
      final requestOptions = RequestOptions(path: '/test');
      final response = Response<dynamic>(
        requestOptions: requestOptions,
        statusCode: 406,
        headers: Headers.fromMap({
          'content-type': ['application/problem+json'],
        }),
        data: <String, dynamic>{
          'type': 'https://example.com/probs/not-acceptable',
          'title': 'Not Acceptable',
          'status': 406,
          'detail': 'Requested media type not supported',
          'instance': '/test',
        },
      );

      final original = DioException(
        requestOptions: requestOptions,
        response: response,
        type: DioExceptionType.badResponse,
      );

      DioException? captured;
      interceptor.onError(
        original,
        _CaptureErrorHandler(onNext: (e) => captured = e),
      );

      expect(captured, isA<ApiException>());
      final apiEx = captured! as ApiException;
      expect(apiEx.problemDetails, isNotNull);
      expect(
        apiEx.problemDetails!.type,
        'https://example.com/probs/not-acceptable',
      );
      expect(apiEx.problemDetails!.status, 406);
      expect(apiEx.errorResponse, isNull);
    });
  });

  // ---------------------------------------------------------------------------
  // onError – ErrorResponse
  // ---------------------------------------------------------------------------

  group('onError – ErrorResponse', () {
    test('parses standard server error response', () {
      final requestOptions = RequestOptions(path: '/test');
      final response = Response<dynamic>(
        requestOptions: requestOptions,
        statusCode: 409,
        headers: Headers.fromMap({
          'content-type': ['application/json'],
        }),
        data: <String, dynamic>{
          'error': 'conflict',
          'message': 'Already exists',
        },
      );

      final original = DioException(
        requestOptions: requestOptions,
        response: response,
        type: DioExceptionType.badResponse,
      );

      DioException? captured;
      interceptor.onError(
        original,
        _CaptureErrorHandler(onNext: (e) => captured = e),
      );

      expect(captured, isA<ApiException>());
      final apiEx = captured! as ApiException;
      expect(apiEx.errorResponse, isNotNull);
      expect(apiEx.errorResponse!.error, 'conflict');
      expect(apiEx.problemDetails, isNull);
    });
  });

  // ---------------------------------------------------------------------------
  // onError – unknown format
  // ---------------------------------------------------------------------------

  group('onError – unknown format', () {
    test('wraps unrecognized response body in ApiException', () {
      final requestOptions = RequestOptions(path: '/test');
      final response = Response<dynamic>(
        requestOptions: requestOptions,
        statusCode: 500,
        data: 'internal server error',
      );

      final original = DioException(
        requestOptions: requestOptions,
        response: response,
        type: DioExceptionType.badResponse,
      );

      DioException? captured;
      interceptor.onError(
        original,
        _CaptureErrorHandler(onNext: (e) => captured = e),
      );

      expect(captured, isA<ApiException>());
      final apiEx = captured! as ApiException;
      expect(apiEx.problemDetails, isNull);
      expect(apiEx.errorResponse, isNull);
    });

    test('passes through errors without a response', () {
      final original = DioException(
        requestOptions: RequestOptions(path: '/test'),
        type: DioExceptionType.connectionTimeout,
      );

      DioException? captured;
      interceptor.onError(
        original,
        _CaptureErrorHandler(onNext: (e) => captured = e),
      );

      expect(captured, isNot(isA<ApiException>()));
      expect(captured!.type, DioExceptionType.connectionTimeout);
    });

    test('does not double-wrap ApiException', () {
      final apiEx = ApiException(
        requestOptions: RequestOptions(path: '/test'),
        errorResponse: ErrorResponse(error: 'already_wrapped'),
      );

      DioException? captured;
      interceptor.onError(
        apiEx,
        _CaptureErrorHandler(onNext: (e) => captured = e),
      );

      expect(identical(captured, apiEx), isTrue);
    });
  });
}

class _CaptureResponseHandler extends ResponseInterceptorHandler {
  _CaptureResponseHandler({this.onNext, this.onReject});

  final void Function(Response<dynamic>)? onNext;
  final void Function(DioException)? onReject;

  @override
  void next(Response<dynamic> response) {
    onNext?.call(response);
  }

  @override
  void reject(
    DioException error, [
    bool callFollowingErrorInterceptor = false,
  ]) {
    onReject?.call(error);
  }

  @override
  void resolve(Response<dynamic> response) {
    onNext?.call(response);
  }
}

class _CaptureErrorHandler extends ErrorInterceptorHandler {
  _CaptureErrorHandler({this.onNext});

  final void Function(DioException)? onNext;

  @override
  void next(DioException error) {
    onNext?.call(error);
  }

  @override
  void resolve(Response<dynamic> response) {}

  @override
  void reject(DioException error) {
    onNext?.call(error);
  }
}
