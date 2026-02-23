import 'crypto_utils.dart' show base64UrlDecode;
import 'jwe_exception.dart';

/// EC P-256 public key in JWK format for JWE encryption.
///
/// Coordinates are unpadded base64url-encoded big-endian byte strings.
class EcPublicJwk {
  EcPublicJwk({required this.x, required this.y});

  /// Creates an [EcPublicJwk] from a JWK JSON map.
  ///
  /// Validates that `kty` is `"EC"` and `crv` is `"P-256"`.
  factory EcPublicJwk.fromJson(Map<String, dynamic> json) {
    final kty = json['kty'] as String?;
    final crv = json['crv'] as String?;
    if (kty != 'EC' || crv != 'P-256') {
      throw JweException('unsupported key type or curve: kty=$kty, crv=$crv');
    }
    final x = json['x'] as String?;
    final y = json['y'] as String?;
    if (x == null || y == null) {
      throw JweException('missing x or y coordinate');
    }
    final xBytes = base64UrlDecode(x);
    final yBytes = base64UrlDecode(y);
    if (xBytes.length != 32 || yBytes.length != 32) {
      throw JweException(
        'invalid P-256 coordinate length: x=${xBytes.length}, y=${yBytes.length}',
      );
    }
    return EcPublicJwk(x: x, y: y);
  }

  /// Unpadded base64url-encoded x coordinate (32 bytes for P-256).
  final String x;

  /// Unpadded base64url-encoded y coordinate (32 bytes for P-256).
  final String y;

  /// Returns the JWK JSON representation.
  Map<String, dynamic> toJson() => {
    'kty': 'EC',
    'crv': 'P-256',
    'x': x,
    'y': y,
  };
}

/// EC P-256 private key in JWK format for JWE decryption.
///
/// Coordinates and private scalar are unpadded base64url-encoded big-endian
/// byte strings.
class EcPrivateJwk {
  EcPrivateJwk({required this.x, required this.y, required this.d});

  /// Creates an [EcPrivateJwk] from a JWK JSON map.
  ///
  /// Validates that `kty` is `"EC"`, `crv` is `"P-256"`, and `d` is present.
  factory EcPrivateJwk.fromJson(Map<String, dynamic> json) {
    final kty = json['kty'] as String?;
    final crv = json['crv'] as String?;
    if (kty != 'EC' || crv != 'P-256') {
      throw JweException('unsupported key type or curve: kty=$kty, crv=$crv');
    }
    final x = json['x'] as String?;
    final y = json['y'] as String?;
    final d = json['d'] as String?;
    if (x == null || y == null || d == null) {
      throw JweException('missing x, y, or d parameter');
    }
    return EcPrivateJwk(x: x, y: y, d: d);
  }

  /// Unpadded base64url-encoded x coordinate.
  final String x;

  /// Unpadded base64url-encoded y coordinate.
  final String y;

  /// Unpadded base64url-encoded private key scalar.
  final String d;

  /// Extracts the corresponding public key.
  EcPublicJwk get publicKey => EcPublicJwk(x: x, y: y);

  /// Returns the JWK JSON representation (includes private material).
  Map<String, dynamic> toJson() => {
    'kty': 'EC',
    'crv': 'P-256',
    'x': x,
    'y': y,
    'd': d,
  };
}
