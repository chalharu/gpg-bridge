import 'package:dio/dio.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';

import 'api_exception.dart';
import 'auth_interceptor.dart';
import 'http_client_provider.dart';
import 'server_url_interceptor.dart';

part 'device_api_service.g.dart';

const _devicePath = '/device';
const _deviceRefreshPath = '$_devicePath/refresh';
const _healthPath = '/health';

class DeviceApiException implements Exception {
  DeviceApiException(this.message, {this.cause});

  final String message;
  final Object? cause;

  @override
  String toString() {
    return cause == null
        ? 'DeviceApiException: $message'
        : 'DeviceApiException: $message ($cause)';
  }
}

class DeviceResponse {
  DeviceResponse({required this.deviceJwt});

  factory DeviceResponse.fromJson(Map<String, dynamic> json) {
    final jwt = json['device_jwt'];
    if (jwt is! String || jwt.isEmpty) {
      throw DeviceApiException('invalid device_jwt in response');
    }
    return DeviceResponse(deviceJwt: jwt);
  }

  final String deviceJwt;
}

class DeviceRefreshResponse {
  DeviceRefreshResponse({required this.deviceJwt});

  factory DeviceRefreshResponse.fromJson(Map<String, dynamic> json) {
    final jwt = json['device_jwt'];
    if (jwt is! String || jwt.isEmpty) {
      throw DeviceApiException('invalid device_jwt in refresh response');
    }
    return DeviceRefreshResponse(deviceJwt: jwt);
  }

  final String deviceJwt;
}

abstract interface class DeviceApiService {
  Future<void> validateServerConnection({required String serverUrl});

  Future<DeviceResponse> registerDevice({
    required String serverUrl,
    required String deviceToken,
    required String firebaseInstallationId,
    required List<Map<String, dynamic>> sigKeys,
    required List<Map<String, dynamic>> encKeys,
    String? defaultKid,
  });

  Future<void> updateDevice({String? deviceToken, String? defaultKid});

  Future<void> deleteDevice();

  Future<DeviceRefreshResponse> refreshDeviceJwt({
    required String currentDeviceJwt,
  });
}

class DefaultDeviceApiService implements DeviceApiService {
  DefaultDeviceApiService({required Dio dio}) : _dio = dio;

  final Dio _dio;

  @override
  Future<void> validateServerConnection({required String serverUrl}) async {
    try {
      await _dio.get<Map<String, dynamic>>(
        _healthPath,
        options: Options(
          extra: {skipAuthExtraKey: true, serverUrlOverrideExtraKey: serverUrl},
        ),
      );
    } catch (error) {
      _rethrowOrWrap(error, 'validate server connection');
    }
  }

  @override
  Future<DeviceResponse> registerDevice({
    required String serverUrl,
    required String deviceToken,
    required String firebaseInstallationId,
    required List<Map<String, dynamic>> sigKeys,
    required List<Map<String, dynamic>> encKeys,
    String? defaultKid,
  }) async {
    try {
      final body = _buildRegisterBody(
        deviceToken: deviceToken,
        firebaseInstallationId: firebaseInstallationId,
        sigKeys: sigKeys,
        encKeys: encKeys,
        defaultKid: defaultKid,
      );
      final response = await _dio.post<Map<String, dynamic>>(
        _devicePath,
        data: body,
        options: Options(
          extra: {skipAuthExtraKey: true, serverUrlOverrideExtraKey: serverUrl},
        ),
      );
      return DeviceResponse.fromJson(response.data!);
    } catch (error) {
      _rethrowOrWrap(error, 'register device');
    }
  }

  @override
  Future<void> updateDevice({String? deviceToken, String? defaultKid}) async {
    if (deviceToken == null && defaultKid == null) {
      throw DeviceApiException('at least one field required for update');
    }
    try {
      final body = <String, dynamic>{
        'device_token': ?deviceToken,
        'default_kid': ?defaultKid,
      };
      await _dio.patch<void>(_devicePath, data: body);
    } catch (error) {
      _rethrowOrWrap(error, 'update device');
    }
  }

  @override
  Future<void> deleteDevice() async {
    try {
      await _dio.delete<void>(_devicePath);
    } catch (error) {
      _rethrowOrWrap(error, 'delete device');
    }
  }

  @override
  Future<DeviceRefreshResponse> refreshDeviceJwt({
    required String currentDeviceJwt,
  }) async {
    try {
      final response = await _dio.post<Map<String, dynamic>>(
        _deviceRefreshPath,
        data: {'device_jwt': currentDeviceJwt},
      );
      return DeviceRefreshResponse.fromJson(response.data!);
    } catch (error) {
      _rethrowOrWrap(error, 'refresh device JWT');
    }
  }

  Map<String, dynamic> _buildRegisterBody({
    required String deviceToken,
    required String firebaseInstallationId,
    required List<Map<String, dynamic>> sigKeys,
    required List<Map<String, dynamic>> encKeys,
    String? defaultKid,
  }) {
    return <String, dynamic>{
      'device_token': deviceToken,
      'firebase_installation_id': firebaseInstallationId,
      'public_key': {
        'keys': {'sig': sigKeys, 'enc': encKeys},
      },
      'default_kid': ?defaultKid,
    };
  }

  Never _rethrowOrWrap(Object error, String operation) {
    if (error is DeviceApiException) throw error;
    if (error is ApiException) throw error;
    throw DeviceApiException('failed to $operation', cause: error);
  }
}

@Riverpod(keepAlive: true)
DeviceApiService deviceApi(Ref ref) {
  return DefaultDeviceApiService(dio: ref.read(httpClientProvider));
}
