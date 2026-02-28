import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/http/api_exception.dart';
import 'package:gpg_bridge_mobile/http/pairing_api_service.dart';

void main() {
  group('PairingApiException', () {
    test('toString includes message without cause', () {
      final error = PairingApiException('pairing failed');

      expect(error.toString(), 'PairingApiException: pairing failed');
    });

    test('toString includes message and cause', () {
      final error = PairingApiException(
        'pairing failed',
        cause: Exception('network'),
      );

      expect(error.toString(), contains('pairing failed'));
      expect(error.toString(), contains('network'));
    });
  });

  group('PairingResponse', () {
    test('fromJson parses valid response', () {
      final response = PairingResponse.fromJson({
        'ok': true,
        'client_id': 'client-abc',
        'pairing_id': 'pair-uuid-123',
      });

      expect(response.clientId, 'client-abc');
      expect(response.pairingId, 'pair-uuid-123');
    });

    test('fromJson throws on missing client_id', () {
      expect(
        () => PairingResponse.fromJson({'ok': true, 'pairing_id': 'pair-uuid'}),
        throwsA(isA<PairingApiException>()),
      );
    });

    test('fromJson throws on empty client_id', () {
      expect(
        () => PairingResponse.fromJson({
          'ok': true,
          'client_id': '',
          'pairing_id': 'pair-uuid',
        }),
        throwsA(isA<PairingApiException>()),
      );
    });

    test('fromJson throws on missing pairing_id', () {
      expect(
        () => PairingResponse.fromJson({'ok': true, 'client_id': 'client-abc'}),
        throwsA(isA<PairingApiException>()),
      );
    });

    test('fromJson throws on empty pairing_id', () {
      expect(
        () => PairingResponse.fromJson({
          'ok': true,
          'client_id': 'client-abc',
          'pairing_id': '',
        }),
        throwsA(isA<PairingApiException>()),
      );
    });
  });

  group('DefaultPairingApiService', () {
    late Dio dio;

    setUp(() {
      dio = Dio(BaseOptions(baseUrl: 'https://api.example.com'));
    });

    test('createPairing sends correct POST body', () async {
      Map<String, dynamic>? capturedBody;

      dio.httpClientAdapter = _MockAdapter((options, _, cancelFuture) async {
        capturedBody = options.data as Map<String, dynamic>?;
        return ResponseBody.fromString(
          '{"ok":true,"client_id":"c1","pairing_id":"p1"}',
          200,
          headers: {
            'content-type': ['application/json'],
          },
        );
      });

      final service = DefaultPairingApiService(dio: dio);

      final response = await service.createPairing(pairingJwt: 'jwt-token');

      expect(response.clientId, 'c1');
      expect(response.pairingId, 'p1');
      expect(capturedBody!['pairing_jwt'], 'jwt-token');
    });

    test('deletePairing sends DELETE to correct path', () async {
      String? capturedPath;
      String? capturedMethod;

      dio.httpClientAdapter = _MockAdapter((options, _, cancelFuture) async {
        capturedPath = options.path;
        capturedMethod = options.method;
        return ResponseBody.fromString('', 204);
      });

      final service = DefaultPairingApiService(dio: dio);

      await service.deletePairing(pairingId: 'uuid-123');

      expect(capturedMethod, 'DELETE');
      expect(capturedPath, contains('/pairing/uuid-123'));
    });

    test('createPairing wraps DioException', () async {
      dio.httpClientAdapter = _MockAdapter((options, _, cancelFuture) async {
        return ResponseBody.fromString(
          '{"error":"bad_request"}',
          400,
          headers: {
            'content-type': ['application/json'],
          },
        );
      });

      final service = DefaultPairingApiService(dio: dio);

      expect(
        () => service.createPairing(pairingJwt: 'jwt'),
        throwsA(anyOf(isA<ApiException>(), isA<PairingApiException>())),
      );
    });

    test('deletePairing wraps 404 error', () async {
      dio.httpClientAdapter = _MockAdapter((options, _, cancelFuture) async {
        return ResponseBody.fromString(
          '{"error":"not_found"}',
          404,
          headers: {
            'content-type': ['application/json'],
          },
        );
      });

      final service = DefaultPairingApiService(dio: dio);

      expect(
        () => service.deletePairing(pairingId: 'missing'),
        throwsA(anyOf(isA<ApiException>(), isA<PairingApiException>())),
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
