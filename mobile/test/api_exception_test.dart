import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/http/api_exception.dart';

void main() {
  // ---------------------------------------------------------------------------
  // ProblemDetails
  // ---------------------------------------------------------------------------

  group('ProblemDetails', () {
    test('parses valid RFC 7807 JSON', () {
      final json = <String, dynamic>{
        'type': 'https://example.com/probs/not-found',
        'title': 'Not Found',
        'status': 404,
        'detail': 'Resource was not found',
        'instance': '/resource/42',
      };

      final pd = ProblemDetails.fromJson(json);

      expect(pd, isNotNull);
      expect(pd!.type, 'https://example.com/probs/not-found');
      expect(pd.title, 'Not Found');
      expect(pd.status, 404);
      expect(pd.detail, 'Resource was not found');
      expect(pd.instance, '/resource/42');
    });

    test('parses without optional instance', () {
      final json = <String, dynamic>{
        'type': 'https://example.com/probs/bad-request',
        'title': 'Bad Request',
        'status': 400,
        'detail': 'Invalid input',
      };

      final pd = ProblemDetails.fromJson(json);

      expect(pd, isNotNull);
      expect(pd!.instance, isNull);
    });

    test('returns null when type is missing', () {
      final json = <String, dynamic>{
        'title': 'Bad Request',
        'status': 400,
        'detail': 'Invalid input',
      };

      expect(ProblemDetails.fromJson(json), isNull);
    });

    test('returns null when status is not an int', () {
      final json = <String, dynamic>{
        'type': 'https://example.com/probs/bad-request',
        'title': 'Bad Request',
        'status': '400',
        'detail': 'Invalid input',
      };

      expect(ProblemDetails.fromJson(json), isNull);
    });

    test('returns null when detail is missing', () {
      final json = <String, dynamic>{
        'type': 'https://example.com/probs/bad-request',
        'title': 'Bad Request',
        'status': 400,
      };

      expect(ProblemDetails.fromJson(json), isNull);
    });

    test('toString contains all fields', () {
      final pd = ProblemDetails(
        type: 'urn:error',
        title: 'Error',
        status: 500,
        detail: 'Internal',
        instance: '/req/1',
      );

      final s = pd.toString();
      expect(s, contains('urn:error'));
      expect(s, contains('Error'));
      expect(s, contains('500'));
      expect(s, contains('Internal'));
      expect(s, contains('/req/1'));
    });
  });

  // ---------------------------------------------------------------------------
  // ErrorResponse
  // ---------------------------------------------------------------------------

  group('ErrorResponse', () {
    test('parses valid server ErrorResponse JSON', () {
      final json = <String, dynamic>{
        'error': 'invalid_request',
        'message': 'The request was malformed',
      };

      final er = ErrorResponse.fromJson(json);

      expect(er, isNotNull);
      expect(er!.error, 'invalid_request');
      expect(er.message, 'The request was malformed');
    });

    test('parses without optional message', () {
      final json = <String, dynamic>{'error': 'unauthorized'};

      final er = ErrorResponse.fromJson(json);

      expect(er, isNotNull);
      expect(er!.error, 'unauthorized');
      expect(er.message, isNull);
    });

    test('returns null when error field is missing', () {
      final json = <String, dynamic>{'message': 'whoops'};

      expect(ErrorResponse.fromJson(json), isNull);
    });

    test('returns null when error is not a string', () {
      final json = <String, dynamic>{'error': 42};

      expect(ErrorResponse.fromJson(json), isNull);
    });

    test('toString contains fields', () {
      final er = ErrorResponse(error: 'bad', message: 'oops');
      final s = er.toString();
      expect(s, contains('bad'));
      expect(s, contains('oops'));
    });
  });

  // ---------------------------------------------------------------------------
  // ApiException
  // ---------------------------------------------------------------------------

  group('ApiException', () {
    test('message delegates to problemDetails.detail', () {
      final ex = ApiException(
        requestOptions: RequestOptions(path: '/test'),
        problemDetails: ProblemDetails(
          type: 'urn:err',
          title: 'Err',
          status: 400,
          detail: 'problem detail message',
        ),
      );

      expect(ex.message, 'problem detail message');
    });

    test('message delegates to errorResponse.message', () {
      final ex = ApiException(
        requestOptions: RequestOptions(path: '/test'),
        errorResponse: ErrorResponse(
          error: 'bad_request',
          message: 'error response message',
        ),
      );

      expect(ex.message, 'error response message');
    });

    test('message delegates to errorResponse.error when message is null', () {
      final ex = ApiException(
        requestOptions: RequestOptions(path: '/test'),
        errorResponse: ErrorResponse(error: 'unauthorized'),
      );

      expect(ex.message, 'unauthorized');
    });

    test('overrideMessage takes priority', () {
      final ex = ApiException(
        requestOptions: RequestOptions(path: '/test'),
        problemDetails: ProblemDetails(
          type: 'urn:err',
          title: 'Err',
          status: 400,
          detail: 'ignored',
        ),
        overrideMessage: 'custom message',
      );

      expect(ex.message, 'custom message');
    });

    test('type is badResponse', () {
      final ex = ApiException(requestOptions: RequestOptions(path: '/test'));

      expect(ex.type, DioExceptionType.badResponse);
    });

    test('toString contains status code', () {
      final ex = ApiException(
        requestOptions: RequestOptions(path: '/test'),
        response: Response<dynamic>(
          requestOptions: RequestOptions(path: '/test'),
          statusCode: 422,
        ),
        errorResponse: ErrorResponse(error: 'validation_error'),
      );

      final s = ex.toString();
      expect(s, contains('422'));
      expect(s, contains('validation_error'));
    });
  });
}
