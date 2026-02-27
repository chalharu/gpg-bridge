import 'dart:convert';

import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/http/api_exception.dart';
import 'package:gpg_bridge_mobile/http/gpg_key_api_service.dart';

void main() {
  group('GpgKeyApiException', () {
    test('toString without cause', () {
      final error = GpgKeyApiException('gpg failed');

      expect(error.toString(), 'GpgKeyApiException: gpg failed');
    });

    test('toString with cause', () {
      final error = GpgKeyApiException(
        'gpg failed',
        cause: Exception('timeout'),
      );

      expect(error.toString(), contains('gpg failed'));
      expect(error.toString(), contains('timeout'));
    });
  });

  group('GpgKeyEntry', () {
    test('fromJson parses valid entry', () {
      final entry = GpgKeyEntry.fromJson({
        'keygrip': 'A' * 40,
        'key_id': 'B' * 16,
        'public_key': {'kty': 'RSA', 'n': 'abc', 'e': 'def'},
      });

      expect(entry.keygrip, 'A' * 40);
      expect(entry.keyId, 'B' * 16);
      expect(entry.publicKey['kty'], 'RSA');
    });

    test('fromJson throws on missing keygrip', () {
      expect(
        () => GpgKeyEntry.fromJson({
          'key_id': 'B' * 16,
          'public_key': {'kty': 'RSA'},
        }),
        throwsA(isA<GpgKeyApiException>()),
      );
    });

    test('fromJson throws on empty keygrip', () {
      expect(
        () => GpgKeyEntry.fromJson({
          'keygrip': '',
          'key_id': 'B' * 16,
          'public_key': {'kty': 'RSA'},
        }),
        throwsA(isA<GpgKeyApiException>()),
      );
    });

    test('fromJson throws on missing key_id', () {
      expect(
        () => GpgKeyEntry.fromJson({
          'keygrip': 'A' * 40,
          'public_key': {'kty': 'RSA'},
        }),
        throwsA(isA<GpgKeyApiException>()),
      );
    });

    test('fromJson throws on missing public_key', () {
      expect(
        () => GpgKeyEntry.fromJson({'keygrip': 'A' * 40, 'key_id': 'B' * 16}),
        throwsA(isA<GpgKeyApiException>()),
      );
    });

    test('toJson produces expected map', () {
      final entry = GpgKeyEntry(
        keygrip: 'grip1',
        keyId: 'id1',
        publicKey: {'kty': 'RSA'},
      );

      final json = entry.toJson();

      expect(json['keygrip'], 'grip1');
      expect(json['key_id'], 'id1');
      expect(json['public_key'], {'kty': 'RSA'});
    });

    test('fromJson/toJson round-trip', () {
      final original = {
        'keygrip': 'A' * 40,
        'key_id': 'B' * 16,
        'public_key': {'kty': 'EC', 'crv': 'P-256'},
      };

      final entry = GpgKeyEntry.fromJson(original);
      final roundTripped = entry.toJson();

      expect(roundTripped['keygrip'], original['keygrip']);
      expect(roundTripped['key_id'], original['key_id']);
      expect(roundTripped['public_key'], original['public_key']);
    });
  });

  group('GpgKeyListResponse', () {
    test('fromJson parses valid response', () {
      final response = GpgKeyListResponse.fromJson({
        'gpg_keys': [
          {
            'keygrip': 'A' * 40,
            'key_id': 'B' * 16,
            'public_key': {'kty': 'RSA'},
          },
        ],
      });

      expect(response.gpgKeys, hasLength(1));
      expect(response.gpgKeys[0].keygrip, 'A' * 40);
    });

    test('fromJson throws on invalid gpg_keys', () {
      expect(
        () => GpgKeyListResponse.fromJson({'gpg_keys': 'not-a-list'}),
        throwsA(isA<GpgKeyApiException>()),
      );
    });

    test('fromJson throws on missing gpg_keys', () {
      expect(
        () => GpgKeyListResponse.fromJson({}),
        throwsA(isA<GpgKeyApiException>()),
      );
    });
  });

  group('DefaultGpgKeyApiService', () {
    late Dio dio;

    setUp(() {
      dio = Dio(BaseOptions(baseUrl: 'https://api.example.com'));
    });

    test('registerGpgKeys sends POST with correct body', () async {
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

      final service = DefaultGpgKeyApiService(dio: dio);

      await service.registerGpgKeys(
        gpgKeys: [
          GpgKeyEntry(
            keygrip: 'grip1',
            keyId: 'id1',
            publicKey: {'kty': 'RSA'},
          ),
        ],
      );

      expect(capturedMethod, 'POST');
      expect(capturedPath, contains('/device/gpg_key'));
      final gpgKeys = capturedBody!['gpg_keys'] as List;
      expect(gpgKeys, hasLength(1));
      expect((gpgKeys[0] as Map)['keygrip'], 'grip1');
    });

    test('listGpgKeys parses response correctly', () async {
      final responseData = {
        'gpg_keys': [
          {
            'keygrip': 'A' * 40,
            'key_id': 'B' * 16,
            'public_key': {'kty': 'RSA', 'n': 'abc'},
          },
        ],
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

      final service = DefaultGpgKeyApiService(dio: dio);

      final result = await service.listGpgKeys();

      expect(result.gpgKeys, hasLength(1));
      expect(result.gpgKeys[0].keygrip, 'A' * 40);
    });

    test('deleteGpgKey sends DELETE with keygrip in path', () async {
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

      final service = DefaultGpgKeyApiService(dio: dio);

      await service.deleteGpgKey(
        keygrip: 'ABCDEF0123456789ABCDEF0123456789ABCDEF01',
      );

      expect(capturedMethod, 'DELETE');
      expect(
        capturedPath,
        contains('/device/gpg_key/ABCDEF0123456789ABCDEF0123456789ABCDEF01'),
      );
    });

    test('deleteGpgKey rejects invalid keygrip format', () async {
      final service = DefaultGpgKeyApiService(dio: dio);

      expect(
        () => service.deleteGpgKey(keygrip: 'not-a-keygrip'),
        throwsA(isA<GpgKeyApiException>()),
      );
    });

    test('registerGpgKeys wraps error as GpgKeyApiException', () async {
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

      final service = DefaultGpgKeyApiService(dio: dio);

      expect(
        () => service.registerGpgKeys(
          gpgKeys: [
            GpgKeyEntry(keygrip: 'g', keyId: 'i', publicKey: {'kty': 'RSA'}),
          ],
        ),
        throwsA(anyOf(isA<GpgKeyApiException>(), isA<ApiException>())),
      );
    });

    test('listGpgKeys wraps error', () async {
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

      final service = DefaultGpgKeyApiService(dio: dio);

      expect(
        () => service.listGpgKeys(),
        throwsA(anyOf(isA<GpgKeyApiException>(), isA<ApiException>())),
      );
    });

    test('deleteGpgKey wraps error', () async {
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

      final service = DefaultGpgKeyApiService(dio: dio);

      expect(
        () => service.deleteGpgKey(
          keygrip: '0000000000000000000000000000000000000000',
        ),
        throwsA(anyOf(isA<GpgKeyApiException>(), isA<ApiException>())),
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
