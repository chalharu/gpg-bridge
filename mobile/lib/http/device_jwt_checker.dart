import 'dart:convert';

/// Holds the `iat` and `exp` timestamps extracted from a JWT payload.
class JwtExpiry {
  const JwtExpiry({required this.issuedAt, required this.expiresAt});

  /// Unix timestamp (seconds) when the JWT was issued.
  final int issuedAt;

  /// Unix timestamp (seconds) when the JWT expires.
  final int expiresAt;
}

/// Pure utility for JWT expiry analysis — no side effects.
abstract final class DeviceJwtChecker {
  /// Extracts `iat` and `exp` from a JWT payload.
  ///
  /// Returns `null` if the JWT is malformed or missing required claims.
  static JwtExpiry? parseExpiry(String jwt) {
    final parts = jwt.split('.');
    if (parts.length != 3) return null;

    try {
      final normalized = base64Url.normalize(parts[1]);
      final payload =
          jsonDecode(utf8.decode(base64Url.decode(normalized)))
              as Map<String, dynamic>;

      final iat = payload['iat'];
      final exp = payload['exp'];
      if (iat is! int || exp is! int) return null;

      return JwtExpiry(issuedAt: iat, expiresAt: exp);
    } catch (_) {
      return null;
    }
  }

  /// Returns `true` if remaining validity is less than 1/3 of total.
  ///
  /// Returns `false` when the JWT is already expired or cannot be parsed.
  /// Use [isExpired] to check for expiration separately.
  static bool needsRefresh(String jwt) {
    final expiry = parseExpiry(jwt);
    if (expiry == null) return false;

    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final totalValidity = expiry.expiresAt - expiry.issuedAt;
    final remaining = expiry.expiresAt - now;

    if (remaining <= 0) return false;
    return remaining < totalValidity ~/ 3;
  }

  /// Returns `true` if the JWT `exp` claim has passed.
  ///
  /// Also returns `true` when the JWT cannot be parsed.
  static bool isExpired(String jwt) {
    final expiry = parseExpiry(jwt);
    if (expiry == null) return true;

    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    return now >= expiry.expiresAt;
  }
}
