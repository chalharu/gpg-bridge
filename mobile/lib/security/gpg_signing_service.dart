import 'dart:typed_data';

import 'gpg_key_material.dart' show readMpi;
import 'gpg_signing_ecdsa.dart';
import 'gpg_signing_rsa.dart';

/// Exception thrown by GPG signing operations.
class GpgSigningException implements Exception {
  GpgSigningException(this.message, {this.cause});

  final String message;
  final Object? cause;

  @override
  String toString() {
    if (cause == null) return 'GpgSigningException: $message';
    return 'GpgSigningException: $message ($cause)';
  }
}

/// Signs pre-computed hashes using GPG secret key material.
abstract interface class GpgSigningService {
  /// Signs [hashBytes] using the GPG secret key.
  ///
  /// Returns raw signature bytes, or `null` if the algorithm is unsupported
  /// (e.g. Ed25519). Throws [GpgSigningException] on failure.
  Uint8List? sign({
    required Uint8List hashBytes,
    required String hashAlgorithm,
    required Uint8List secretMaterial,
    required Map<String, dynamic> publicKeyJwk,
  });
}

class DefaultGpgSigningService implements GpgSigningService {
  @override
  Uint8List? sign({
    required Uint8List hashBytes,
    required String hashAlgorithm,
    required Uint8List secretMaterial,
    required Map<String, dynamic> publicKeyJwk,
  }) {
    final kty = publicKeyJwk['kty'] as String?;
    try {
      return switch (kty) {
        'RSA' => signRsa(
          hashBytes,
          hashAlgorithm,
          secretMaterial,
          publicKeyJwk,
        ),
        'EC' => signEcdsa(hashBytes, secretMaterial, publicKeyJwk),
        _ => null, // OKP (Ed25519) and others unsupported
      };
    } catch (e) {
      if (e is GpgSigningException) rethrow;
      throw GpgSigningException('signing failed', cause: e);
    }
  }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Validates the OpenPGP V4 unencrypted secret key checksum.
///
/// The checksum is the sum of all secret MPI bytes (from offset 1 to
/// [checksumOffset]) mod 65536, stored as 2 big-endian bytes.
void validateSecretChecksum(Uint8List data, int checksumOffset) {
  if (checksumOffset + 2 > data.length) {
    throw GpgSigningException('secret material too short for checksum');
  }
  final expected = (data[checksumOffset] << 8) | data[checksumOffset + 1];
  var actual = 0;
  for (var i = 1; i < checksumOffset; i++) {
    actual = (actual + data[i]) & 0xFFFF;
  }
  if (actual != expected) {
    throw GpgSigningException('secret key checksum mismatch');
  }
}

/// Parses RSA secret MPIs: d, p, q, u (u is discarded).
/// Validates the trailing 2-byte checksum.
(BigInt d, BigInt p, BigInt q) parseRsaSecret(Uint8List data) {
  if (data.isEmpty || data[0] != 0) {
    throw GpgSigningException('encrypted key not supported (S2K != 0)');
  }
  var offset = 1;
  final (d, afterD) = readMpi(data, offset);
  final (p, afterP) = readMpi(data, afterD);
  final (q, afterQ) = readMpi(data, afterP);
  // u (inverse of p mod q) — skip, pointycastle computes internally.
  final (_, afterU) = readMpi(data, afterQ);
  validateSecretChecksum(data, afterU);
  return (d, p, q);
}

/// Parses ECDSA secret MPI: d scalar.
/// Validates the trailing 2-byte checksum.
BigInt parseEcdsaSecret(Uint8List data) {
  if (data.isEmpty || data[0] != 0) {
    throw GpgSigningException('encrypted key not supported (S2K != 0)');
  }
  final (d, afterD) = readMpi(data, 1);
  validateSecretChecksum(data, afterD);
  return d;
}

/// Zeroes all bytes in [data].
void zeroFill(Uint8List data) {
  data.fillRange(0, data.length, 0);
}
