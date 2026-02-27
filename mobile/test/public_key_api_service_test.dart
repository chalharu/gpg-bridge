import 'dart:convert';

import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/http/api_exception.dart';
import 'package:gpg_bridge_mobile/http/public_key_api_service.dart';

void main() {
  group('PublicKeyApiException', () {
    test('toString without cause', () {
      final error = PublicKeyApiException('something failed');

      expect(error.toString(), 'PublicKeyApiException: something failed');
    });

    test('toString with cause', () {
      final error = PublicKeyApiException(
        'something failed',
        cause: Exception('network'),
      );

      expect(error.toString(), contains('something failed'));
      expect(error.toString(), contains('network'));
    });
  });

  group('PublicKeyListResponse', () {
    test('fromJson parses valid response', () {
      final response = PublicKeyListResponse.fromJson({
        'keys': [
          {'kty': 'EC', 'crv': 'P-256'},
        ],
        'default_kid': 'kid-123',
      });

      expect(response.keys, hasLength(1));
      expect(response.defaultKid, 'kid-123');
    });

    test('fromJson throws on invalid keys', () {
      expect(
        () => PublicKeyListResponse.fromJson({
          'keys': 'not-a-list',
          'default_kid': 'kid-123',
        }),
        throwsA(isA<PublicKeyApiException>()),
      );
    });

    test('fromJson throws on missing default_kid', () {
      expect(
        () => PublicKeyListResponse.fromJson({'keys': []}),
        throwsA(isA<PublicKeyApiException>()),
      );
    });

    test('fromJson throws on empty default_kid', () {
      expect(
        () => PublicKeyListResponse.fromJson({'keys': [], 'default_kid': ''}),
        throwsA(isA<PublicKeyApiException>()),
      );
    });
  });

  group('DefaultPublicKeyApiService', () {
    late Dio dio;

    setUp(() {
      dio = Dio(BaseOptions(baseUrl: 'https://api.example.com'));
    });

    test('addPublicKeys sends POST with correct body', () async {
      Map<String, dynamic>? capturedBody;
      String? capturedMethod;
      String? capturedPath;

      dio.httpClientAdapter = _MockAdapter((
        options,
        requestStream,
        cancelFuture,
      ) async {
        capturedBody = options.data as Map<String, dynamic>?;
        capturedMethod = options.method;
        capturedPath = options.path;
        return ResponseBody.fromString('', 204);
      });

      final service = DefaultPublicKeyApiService(dio: dio);

      await service.addPublicKeys(
        keys: [
          {'kty': 'EC', 'crv': 'P-256'},
        ],
      );

      expect(capturedMethod, 'POST');
      expect(capturedPath, contains('/device/public_key'));
      expect(capturedBody!['keys'], hasLength(1));
    });

    test('addPublicKeys includes defaultKid when provided', () async {
      Map<String, dynamic>? capturedBody;

      dio.httpClientAdapter = _MockAdapter((
        options,
        requestStream,
        cancelFuture,
      ) async {
        capturedBody = options.data as Map<String, dynamic>?;
        return ResponseBody.fromString('', 204);
      });

      final service = DefaultPublicKeyApiService(dio: dio);

      await service.addPublicKeys(
        keys: [
          {'kty': 'EC'},
        ],
        defaultKid: 'my-kid',
      );

      expect(capturedBody!['default_kid'], 'my-kid');
    });

    test('listPublicKeys parses response correctly', () async {
      final responseData = {
        'keys': [
          {'kty': 'EC', 'crv': 'P-256', 'kid': 'k1'},
        ],
        'default_kid': 'k1',
      };

      dio.httpClientAdapter = _MockAdapter((
        options,
        requestStream,
        cancelFuture,
      ) async {
        return ResponseBody.fromString(
          jsonEncode(responseData),
          200,
          headers: {
            'content-type': ['application/json'],
          },
        );
      });

      final service = DefaultPublicKeyApiService(dio: dio);

      final result = await service.listPublicKeys();

      expect(result.keys, hasLength(1));
      expect(result.defaultKid, 'k1');
    });

    test('deletePublicKey sends DELETE with kid in path', () async {
      String? capturedMethod;
      String? capturedPath;

      dio.httpClientAdapter = _MockAdapter((
        options,
        requestStream,
        cancelFuture,
      ) async {
        capturedMethod = options.method;
        capturedPath = options.path;
        return ResponseBody.fromString('', 204);
      });

      final service = DefaultPublicKeyApiService(dio: dio);

      await service.deletePublicKey(
        kid: '550e8400-e29b-41d4-a716-446655440000',
      );

      expect(capturedMethod, 'DELETE');
      expect(
        capturedPath,
        contains('/device/public_key/550e8400-e29b-41d4-a716-446655440000'),
      );
    });

    test('deletePublicKey rejects invalid kid format', () async {
      final service = DefaultPublicKeyApiService(dio: dio);

      expect(
        () => service.deletePublicKey(kid: 'not-a-uuid'),
        throwsA(isA<PublicKeyApiException>()),
      );
    });

    test('addPublicKeys wraps error as PublicKeyApiException', () async {
      dio.httpClientAdapter = _MockAdapter((
        options,
        requestStream,
        cancelFuture,
      ) async {
        return ResponseBody.fromString(
          '{"error":"bad_request"}',
          400,
          headers: {
            'content-type': ['application/json'],
          },
        );
      });

      final service = DefaultPublicKeyApiService(dio: dio);

      expect(
        () => service.addPublicKeys(keys: [{}]),
        throwsA(anyOf(isA<PublicKeyApiException>(), isA<ApiException>())),
      );
    });

    test('listPublicKeys wraps error', () async {
      dio.httpClientAdapter = _MockAdapter((
        options,
        requestStream,
        cancelFuture,
      ) async {
        return ResponseBody.fromString(
          '{"error":"unauthorized"}',
          401,
          headers: {
            'content-type': ['application/json'],
          },
        );
      });

      final service = DefaultPublicKeyApiService(dio: dio);

      expect(
        () => service.listPublicKeys(),
        throwsA(anyOf(isA<PublicKeyApiException>(), isA<ApiException>())),
      );
    });

    test('deletePublicKey wraps error', () async {
      dio.httpClientAdapter = _MockAdapter((
        options,
        requestStream,
        cancelFuture,
      ) async {
        return ResponseBody.fromString(
          '{"error":"not_found"}',
          404,
          headers: {
            'content-type': ['application/json'],
          },
        );
      });

      final service = DefaultPublicKeyApiService(dio: dio);

      expect(
        () => service.deletePublicKey(
          kid: '550e8400-e29b-41d4-a716-446655440000',
        ),
        throwsA(anyOf(isA<PublicKeyApiException>(), isA<ApiException>())),
      );
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
