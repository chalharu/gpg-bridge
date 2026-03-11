import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/http/api_exception.dart';
import 'package:gpg_bridge_mobile/http/auth_interceptor.dart';
import 'package:gpg_bridge_mobile/http/device_api_service.dart';
import 'package:gpg_bridge_mobile/http/server_url_interceptor.dart';

void main() {
  group('DeviceApiException', () {
    test('toString includes message without cause', () {
      final error = DeviceApiException('api failed');

      expect(error.toString(), 'DeviceApiException: api failed');
    });

    test('toString includes message and cause', () {
      final error = DeviceApiException(
        'api failed',
        cause: Exception('network'),
      );

      expect(error.toString(), contains('api failed'));
      expect(error.toString(), contains('network'));
    });
  });

  group('DeviceResponse', () {
    test('fromJson parses valid response', () {
      final response = DeviceResponse.fromJson({
        'device_jwt': 'jwt-token-value',
      });

      expect(response.deviceJwt, 'jwt-token-value');
    });

    test('fromJson throws on missing device_jwt', () {
      expect(
        () => DeviceResponse.fromJson({}),
        throwsA(isA<DeviceApiException>()),
      );
    });

    test('fromJson throws on empty device_jwt', () {
      expect(
        () => DeviceResponse.fromJson({'device_jwt': ''}),
        throwsA(isA<DeviceApiException>()),
      );
    });
  });

  group('DeviceRefreshResponse', () {
    test('fromJson parses valid response', () {
      final response = DeviceRefreshResponse.fromJson({
        'device_jwt': 'new-jwt',
      });

      expect(response.deviceJwt, 'new-jwt');
    });

    test('fromJson throws on missing device_jwt', () {
      expect(
        () => DeviceRefreshResponse.fromJson({}),
        throwsA(isA<DeviceApiException>()),
      );
    });
  });

  group('DefaultDeviceApiService', () {
    late Dio dio;

    setUp(() {
      dio = Dio(BaseOptions(baseUrl: 'https://api.example.com'));
    });

    test('registerDevice sends correct POST body', () async {
      Map<String, dynamic>? capturedBody;
      Map<String, dynamic>? capturedExtra;

      dio.httpClientAdapter = _MockAdapter((options, _, cancelFuture) async {
        capturedBody = options.data as Map<String, dynamic>?;
        capturedExtra = options.extra;
        return ResponseBody.fromString(
          '{"device_jwt":"new-jwt"}',
          201,
          headers: {
            'content-type': ['application/json'],
          },
        );
      });

      final service = DefaultDeviceApiService(dio: dio);

      final response = await service.registerDevice(
        serverUrl: 'https://runtime.example.com',
        deviceToken: 'fcm-token',
        firebaseInstallationId: 'fid-123',
        sigKeys: [
          {'kty': 'EC', 'crv': 'P-256', 'x': 'x1', 'y': 'y1'},
        ],
        encKeys: [
          {'kty': 'EC', 'crv': 'P-256', 'x': 'x2', 'y': 'y2'},
        ],
        defaultKid: 'kid-uuid',
      );

      expect(response.deviceJwt, 'new-jwt');
      expect(capturedBody!['device_token'], 'fcm-token');
      expect(capturedBody!['firebase_installation_id'], 'fid-123');
      expect(capturedBody!['default_kid'], 'kid-uuid');
      expect(capturedBody!['public_key']['keys']['sig'], isNotEmpty);
      expect(capturedBody!['public_key']['keys']['enc'], isNotEmpty);
      expect(
        capturedExtra?[serverUrlOverrideExtraKey],
        'https://runtime.example.com',
      );
    });

    test('registerDevice sets skipAuth extra flag', () async {
      Map<String, dynamic>? capturedExtra;

      dio.httpClientAdapter = _MockAdapter((options, _, cancelFuture) async {
        capturedExtra = options.extra;
        return ResponseBody.fromString(
          '{"device_jwt":"jwt"}',
          201,
          headers: {
            'content-type': ['application/json'],
          },
        );
      });

      final service = DefaultDeviceApiService(dio: dio);

      await service.registerDevice(
        serverUrl: 'https://runtime.example.com',
        deviceToken: 'tok',
        firebaseInstallationId: 'fid',
        sigKeys: [{}],
        encKeys: [{}],
      );

      expect(capturedExtra?['skipAuth'], isTrue);
    });

    test('registerDevice without defaultKid omits field', () async {
      Map<String, dynamic>? capturedBody;

      dio.httpClientAdapter = _MockAdapter((options, _, cancelFuture) async {
        capturedBody = options.data as Map<String, dynamic>?;
        return ResponseBody.fromString(
          '{"device_jwt":"jwt"}',
          201,
          headers: {
            'content-type': ['application/json'],
          },
        );
      });

      final service = DefaultDeviceApiService(dio: dio);

      await service.registerDevice(
        serverUrl: 'https://runtime.example.com',
        deviceToken: 'tok',
        firebaseInstallationId: 'fid',
        sigKeys: [{}],
        encKeys: [{}],
      );

      expect(capturedBody!.containsKey('default_kid'), isFalse);
    });

    test('updateDevice sends PATCH with deviceToken', () async {
      String? capturedPath;
      String? capturedMethod;

      dio.httpClientAdapter = _MockAdapter((options, _, cancelFuture) async {
        capturedPath = options.path;
        capturedMethod = options.method;
        return ResponseBody.fromString('', 204);
      });

      final service = DefaultDeviceApiService(dio: dio);

      await service.updateDevice(deviceToken: 'new-fcm-token');

      expect(capturedMethod, 'PATCH');
      expect(capturedPath, contains('/device'));
    });

    test('updateDevice throws when no fields provided', () async {
      final service = DefaultDeviceApiService(dio: dio);

      expect(() => service.updateDevice(), throwsA(isA<DeviceApiException>()));
    });

    test('deleteDevice sends DELETE request', () async {
      String? capturedMethod;

      dio.httpClientAdapter = _MockAdapter((options, _, cancelFuture) async {
        capturedMethod = options.method;
        return ResponseBody.fromString('', 204);
      });

      final service = DefaultDeviceApiService(dio: dio);

      await service.deleteDevice();

      expect(capturedMethod, 'DELETE');
    });

    test('refreshDeviceJwt sends POST with current JWT', () async {
      Map<String, dynamic>? capturedBody;

      dio.httpClientAdapter = _MockAdapter((options, _, cancelFuture) async {
        capturedBody = options.data as Map<String, dynamic>?;
        return ResponseBody.fromString(
          '{"device_jwt":"refreshed-jwt"}',
          200,
          headers: {
            'content-type': ['application/json'],
          },
        );
      });

      final service = DefaultDeviceApiService(dio: dio);

      final response = await service.refreshDeviceJwt(
        currentDeviceJwt: 'old-jwt',
      );

      expect(response.deviceJwt, 'refreshed-jwt');
      expect(capturedBody!['device_jwt'], 'old-jwt');
    });

    test('registerDevice wraps DioException in ApiException', () async {
      dio.httpClientAdapter = _MockAdapter((options, _, cancelFuture) async {
        return ResponseBody.fromString(
          '{"error":"bad_request"}',
          400,
          headers: {
            'content-type': ['application/json'],
          },
        );
      });

      final service = DefaultDeviceApiService(dio: dio);

      expect(
        () => service.registerDevice(
          serverUrl: 'https://runtime.example.com',
          deviceToken: 'tok',
          firebaseInstallationId: 'fid',
          sigKeys: [{}],
          encKeys: [{}],
        ),
        throwsA(anyOf(isA<ApiException>(), isA<DeviceApiException>())),
      );
    });

    test('registerDevice wraps 409 Conflict as DeviceApiException', () async {
      dio.httpClientAdapter = _MockAdapter((options, _, cancelFuture) async {
        return ResponseBody.fromString(
          '{"error": "FID already registered"}',
          409,
          headers: {
            'content-type': ['application/json'],
          },
        );
      });

      final service = DefaultDeviceApiService(dio: dio);

      expect(
        () => service.registerDevice(
          serverUrl: 'https://runtime.example.com',
          deviceToken: 'test',
          firebaseInstallationId: 'fid',
          sigKeys: [
            {'kty': 'EC'},
          ],
          encKeys: [
            {'kty': 'EC'},
          ],
        ),
        throwsA(anyOf(isA<ApiException>(), isA<DeviceApiException>())),
      );
    });

    test(
      'validateServerConnection sends unauthenticated health check',
      () async {
        String? capturedPath;
        Map<String, dynamic>? capturedExtra;

        dio.httpClientAdapter = _MockAdapter((options, _, cancelFuture) async {
          capturedPath = options.path;
          capturedExtra = options.extra;
          return ResponseBody.fromString(
            '{"status":"ok"}',
            200,
            headers: {
              'content-type': ['application/json'],
            },
          );
        });

        final service = DefaultDeviceApiService(dio: dio);

        await service.validateServerConnection(
          serverUrl: 'https://runtime.example.com',
        );

        expect(capturedPath, '/health');
        expect(capturedExtra?[skipAuthExtraKey], isTrue);
        expect(
          capturedExtra?[serverUrlOverrideExtraKey],
          'https://runtime.example.com',
        );
      },
    );

    test('validateServerConnection wraps failures as API exceptions', () async {
      dio.httpClientAdapter = _MockAdapter((options, _, cancelFuture) async {
        return ResponseBody.fromString(
          '{"error":"unavailable"}',
          503,
          headers: {
            'content-type': ['application/json'],
          },
        );
      });

      final service = DefaultDeviceApiService(dio: dio);

      expect(
        () => service.validateServerConnection(
          serverUrl: 'https://runtime.example.com',
        ),
        throwsA(anyOf(isA<ApiException>(), isA<DeviceApiException>())),
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
