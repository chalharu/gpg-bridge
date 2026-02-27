import 'dart:convert';

import 'package:riverpod_annotation/riverpod_annotation.dart';
import 'package:uuid/uuid.dart';

import 'crypto_utils.dart';
import 'keystore_platform_service.dart';

part 'device_assertion_jwt_service.g.dart';

class DeviceAssertionJwtException implements Exception {
  DeviceAssertionJwtException(this.message, {this.cause});

  final String message;
  final Object? cause;

  @override
  String toString() {
    if (cause == null) {
      return 'DeviceAssertionJwtException: $message';
    }
    return 'DeviceAssertionJwtException: $message ($cause)';
  }
}

/// Abstraction for clock and UUID generation (testable).
abstract interface class JwtClock {
  DateTime now();
  String generateJti();
}

/// Default implementation using real clock and UUID v4.
class DefaultJwtClock implements JwtClock {
  const DefaultJwtClock();

  static const Uuid _uuid = Uuid();

  @override
  DateTime now() => DateTime.now().toUtc();

  @override
  String generateJti() => _uuid.v4();
}

/// Service to generate device_assertion_jwt tokens (OIDC private_key_jwt
/// style) signed with ES256 using the device key from the platform keystore.
abstract interface class DeviceAssertionJwtService {
  /// Generates a signed JWT for the given [firebaseInstallationId] and
  /// [audience] (the API endpoint URL).
  Future<String> generate({
    required String firebaseInstallationId,
    required String audience,
    required String kid,
  });
}

class DefaultDeviceAssertionJwtService implements DeviceAssertionJwtService {
  DefaultDeviceAssertionJwtService({
    required KeystorePlatformService keystoreService,
    JwtClock? clock,
  }) : _keystoreService = keystoreService,
       _clock = clock ?? const DefaultJwtClock();

  final KeystorePlatformService _keystoreService;
  final JwtClock _clock;

  static const int _expirySeconds = 60;

  @override
  Future<String> generate({
    required String firebaseInstallationId,
    required String audience,
    required String kid,
  }) async {
    try {
      return await _generateInternal(
        firebaseInstallationId: firebaseInstallationId,
        audience: audience,
        kid: kid,
      );
    } catch (error) {
      if (error is DeviceAssertionJwtException) rethrow;
      throw DeviceAssertionJwtException(
        'failed to generate device assertion JWT',
        cause: error,
      );
    }
  }

  Future<String> _generateInternal({
    required String firebaseInstallationId,
    required String audience,
    required String kid,
  }) async {
    final header = _buildHeader(kid: kid);
    final payload = _buildPayload(
      firebaseInstallationId: firebaseInstallationId,
      audience: audience,
    );

    final signingInput = '$header.$payload';
    final signingInputBytes = utf8.encode(signingInput);

    final signatureBase64 = await _keystoreService.sign(
      alias: KeystoreAliases.deviceKey,
      data: signingInputBytes,
    );

    // The keystore returns raw R||S signature (base64-encoded).
    // Convert from standard base64 to unpadded base64url.
    final signatureBytes = base64Decode(signatureBase64);
    final signatureBase64Url = base64UrlEncode(signatureBytes);

    return '$signingInput.$signatureBase64Url';
  }

  String _buildHeader({required String kid}) {
    return base64UrlEncodeJson({'alg': 'ES256', 'typ': 'JWT', 'kid': kid});
  }

  String _buildPayload({
    required String firebaseInstallationId,
    required String audience,
  }) {
    final now = _clock.now();
    final claims = <String, dynamic>{
      'iss': firebaseInstallationId,
      'sub': firebaseInstallationId,
      'aud': audience,
      'exp':
          now
              .add(const Duration(seconds: _expirySeconds))
              .millisecondsSinceEpoch ~/
          1000,
      'iat': now.millisecondsSinceEpoch ~/ 1000,
      'jti': _clock.generateJti(),
    };
    return base64UrlEncodeJson(claims);
  }
}

@Riverpod(keepAlive: true)
DeviceAssertionJwtService deviceAssertionJwt(Ref ref) {
  return DefaultDeviceAssertionJwtService(
    keystoreService: ref.read(keystorePlatformProvider),
  );
}

@Riverpod(keepAlive: true)
KeystorePlatformService keystorePlatform(Ref ref) {
  return MethodChannelKeystorePlatformService();
}
