import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/http/api_exception.dart';
import 'package:gpg_bridge_mobile/http/sign_request_api_service.dart';

void main() {
  group('SignRequestApiException', () {
    test('toString includes message without cause', () {
      final error = SignRequestApiException('api failed');

      expect(error.toString(), 'SignRequestApiException: api failed');
    });

    test('toString includes message and cause', () {
      final error = SignRequestApiException(
        'api failed',
        cause: Exception('network'),
      );

      expect(error.toString(), contains('api failed'));
      expect(error.toString(), contains('network'));
    });
  });

  group('SignRequestDetail', () {
    test('fromJson parses valid response', () {
      final detail = SignRequestDetail.fromJson({
        'request_id': 'req-1',
        'sign_jwt': 'jwt.token.here',
        'encrypted_payload': 'a.b.c.d.e',
        'pairing_id': 'pair-1',
        'daemon_enc_public_key': {
          'kty': 'EC',
          'crv': 'P-256',
          'x': 'dGVzdHgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          'y': 'dGVzdHkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        },
      });

      expect(detail.requestId, 'req-1');
      expect(detail.signJwt, 'jwt.token.here');
      expect(detail.encryptedPayload, 'a.b.c.d.e');
      expect(detail.pairingId, 'pair-1');
    });

    test('fromJson throws on missing request_id', () {
      expect(
        () => SignRequestDetail.fromJson({
          'sign_jwt': 'jwt',
          'encrypted_payload': 'a.b.c.d.e',
          'pairing_id': 'pair-1',
          'daemon_enc_public_key': {
            'kty': 'EC',
            'crv': 'P-256',
            'x': 'dGVzdHgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            'y': 'dGVzdHkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          },
        }),
        throwsA(isA<SignRequestApiException>()),
      );
    });

    test('fromJson throws on empty sign_jwt', () {
      expect(
        () => SignRequestDetail.fromJson({
          'request_id': 'req-1',
          'sign_jwt': '',
          'encrypted_payload': 'a.b.c.d.e',
          'pairing_id': 'pair-1',
          'daemon_enc_public_key': {
            'kty': 'EC',
            'crv': 'P-256',
            'x': 'dGVzdHgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            'y': 'dGVzdHkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          },
        }),
        throwsA(isA<SignRequestApiException>()),
      );
    });

    test('fromJson throws on missing encrypted_payload', () {
      expect(
        () => SignRequestDetail.fromJson({
          'request_id': 'req-1',
          'sign_jwt': 'jwt',
          'pairing_id': 'pair-1',
          'daemon_enc_public_key': {
            'kty': 'EC',
            'crv': 'P-256',
            'x': 'dGVzdHgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            'y': 'dGVzdHkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          },
        }),
        throwsA(isA<SignRequestApiException>()),
      );
    });

    test('fromJson throws on missing pairing_id', () {
      expect(
        () => SignRequestDetail.fromJson({
          'request_id': 'req-1',
          'sign_jwt': 'jwt',
          'encrypted_payload': 'a.b.c.d.e',
          'daemon_enc_public_key': {
            'kty': 'EC',
            'crv': 'P-256',
            'x': 'dGVzdHgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            'y': 'dGVzdHkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          },
        }),
        throwsA(isA<SignRequestApiException>()),
      );
    });

    test('fromJson throws on invalid daemon_enc_public_key', () {
      expect(
        () => SignRequestDetail.fromJson({
          'request_id': 'req-1',
          'sign_jwt': 'jwt',
          'encrypted_payload': 'a.b.c.d.e',
          'pairing_id': 'pair-1',
          'daemon_enc_public_key': 'not-a-map',
        }),
        throwsA(isA<SignRequestApiException>()),
      );
    });
  });

  group('SignRequestListResponse', () {
    test('fromJson parses empty requests list', () {
      final response = SignRequestListResponse.fromJson({'requests': []});

      expect(response.requests, isEmpty);
    });

    test('fromJson parses multiple requests', () {
      final response = SignRequestListResponse.fromJson({
        'requests': [
          {
            'request_id': 'req-1',
            'sign_jwt': 'jwt1',
            'encrypted_payload': 'a.b.c.d.e',
            'pairing_id': 'pair-1',
            'daemon_enc_public_key': {
              'kty': 'EC',
              'crv': 'P-256',
              'x': 'dGVzdHgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
              'y': 'dGVzdHkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            },
          },
        ],
      });

      expect(response.requests, hasLength(1));
      expect(response.requests.first.requestId, 'req-1');
    });

    test('fromJson throws on missing requests field', () {
      expect(
        () => SignRequestListResponse.fromJson({}),
        throwsA(isA<SignRequestApiException>()),
      );
    });

    test('fromJson throws on non-list requests', () {
      expect(
        () => SignRequestListResponse.fromJson({'requests': 'not-a-list'}),
        throwsA(isA<SignRequestApiException>()),
      );
    });
  });

  group('DefaultSignRequestApiService', () {
    late Dio dio;

    setUp(() {
      dio = Dio(BaseOptions(baseUrl: 'https://api.example.com'));
    });

    test('getSignRequests sends GET /sign-request', () async {
      String? capturedMethod;
      String? capturedPath;

      dio.httpClientAdapter = _MockAdapter((options, _, _) async {
        capturedMethod = options.method;
        capturedPath = options.path;
        return ResponseBody.fromString(
          '{"requests":[]}',
          200,
          headers: {
            'content-type': ['application/json'],
          },
        );
      });

      final service = DefaultSignRequestApiService(dio: dio);
      final response = await service.getSignRequests();

      expect(capturedMethod, 'GET');
      expect(capturedPath, contains('/sign-request'));
      expect(response.requests, isEmpty);
    });

    test('getSignRequests wraps DioException', () async {
      dio.httpClientAdapter = _MockAdapter((options, _, _) async {
        return ResponseBody.fromString(
          '{"error": "unauthorized"}',
          401,
          headers: {
            'content-type': ['application/json'],
          },
        );
      });

      final service = DefaultSignRequestApiService(dio: dio);

      expect(
        () => service.getSignRequests(),
        throwsA(anyOf(isA<ApiException>(), isA<SignRequestApiException>())),
      );
    });

    test('postSignResult sends POST with sign_jwt Bearer auth', () async {
      Map<String, dynamic>? capturedBody;
      Map<String, dynamic>? capturedHeaders;
      Map<String, dynamic>? capturedExtra;

      dio.httpClientAdapter = _MockAdapter((options, _, _) async {
        capturedBody = options.data as Map<String, dynamic>?;
        capturedHeaders = options.headers;
        capturedExtra = options.extra;
        return ResponseBody.fromString('', 204);
      });

      final service = DefaultSignRequestApiService(dio: dio);
      await service.postSignResult(signJwt: 'sign-jwt-token', status: 'denied');

      expect(capturedBody!['status'], 'denied');
      expect(capturedBody!.containsKey('signature'), isFalse);
      expect(capturedHeaders!['Authorization'], 'Bearer sign-jwt-token');
      expect(capturedExtra!['skipAuth'], isTrue);
    });

    test('postSignResult includes signature when provided', () async {
      Map<String, dynamic>? capturedBody;

      dio.httpClientAdapter = _MockAdapter((options, _, _) async {
        capturedBody = options.data as Map<String, dynamic>?;
        return ResponseBody.fromString('', 204);
      });

      final service = DefaultSignRequestApiService(dio: dio);
      await service.postSignResult(
        signJwt: 'jwt',
        status: 'approved',
        signature: 'jwe-encrypted-sig',
      );

      expect(capturedBody!['status'], 'approved');
      expect(capturedBody!['signature'], 'jwe-encrypted-sig');
    });
  });
}

typedef _AdapterCallback =
    Future<ResponseBody> Function(
      RequestOptions options,
      Stream<List<int>>? requestStream,
      Future<void>? cancelFuture,
    );

class _MockAdapter implements HttpClientAdapter {
  _MockAdapter(this._callback);

  final _AdapterCallback _callback;

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<List<int>>? requestStream,
    Future<void>? cancelFuture,
  ) {
    return _callback(options, requestStream, cancelFuture);
  }

  @override
  void close({bool force = false}) {}
}
