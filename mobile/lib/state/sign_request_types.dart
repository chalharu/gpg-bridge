import '../http/sign_request_api_service.dart';
import '../security/ec_jwk.dart';

/// Exception thrown by sign request operations.
class SignRequestException implements Exception {
  SignRequestException(this.message, {this.cause});

  final String message;
  final Object? cause;

  @override
  String toString() {
    if (cause == null) return 'SignRequestException: $message';
    return 'SignRequestException: $message ($cause)';
  }
}

/// Status of a sign request result.
enum SignResultStatus {
  approved('approved'),
  denied('denied'),
  unavailable('unavailable');

  const SignResultStatus(this.value);

  final String value;
}

/// A decrypted sign request ready for user display.
class DecryptedSignRequest {
  DecryptedSignRequest({
    required this.requestId,
    required this.signJwt,
    required this.hash,
    required this.hashAlgorithm,
    required this.keyId,
    required this.pairingId,
    required this.daemonEncPublicKey,
    required this.receivedAt,
  });

  /// Creates a [DecryptedSignRequest] from a [SignRequestDetail] and
  /// decrypted payload fields.
  factory DecryptedSignRequest.fromDetail({
    required SignRequestDetail detail,
    required String hash,
    required String hashAlgorithm,
    required String keyId,
  }) {
    return DecryptedSignRequest(
      requestId: detail.requestId,
      signJwt: detail.signJwt,
      hash: hash,
      hashAlgorithm: hashAlgorithm,
      keyId: keyId,
      pairingId: detail.pairingId,
      daemonEncPublicKey: detail.daemonEncPublicKey,
      receivedAt: DateTime.now(),
    );
  }

  final String requestId;
  final String signJwt;
  final String hash;
  final String hashAlgorithm;
  final String keyId;
  final String pairingId;
  final EcPublicJwk daemonEncPublicKey;
  final DateTime receivedAt;

  /// Returns the expiry time (5 minutes from reception).
  DateTime get expiresAt => receivedAt.add(const Duration(minutes: 5));

  /// Whether this request has expired.
  bool get isExpired => DateTime.now().isAfter(expiresAt);
}
