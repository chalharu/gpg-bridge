// Types used by the key management service.

import 'dart:typed_data';

import '../http/gpg_key_api_service.dart';
import '../http/public_key_api_service.dart';
import '../security/gpg_key_models.dart';

/// Exception thrown by [KeyManagementService] operations.
class KeyManagementException implements Exception {
  KeyManagementException(this.message, {this.cause});

  final String message;
  final Object? cause;

  @override
  String toString() {
    if (cause == null) {
      return 'KeyManagementException: $message';
    }
    return 'KeyManagementException: $message ($cause)';
  }
}

/// Orchestrates E2E public key and GPG key management.
abstract interface class KeyManagementService {
  /// List E2E public keys from server.
  Future<PublicKeyListResponse> listPublicKeys();

  /// Generate a new E2E key pair and register with server.
  Future<void> addE2eKeyPair();

  /// Delete an E2E public key by kid.
  Future<void> deletePublicKey(String kid);

  /// Parse GPG armored key and return parsed keys for preview.
  List<GpgParsedKey> parseGpgArmoredKey(String armoredKey);

  /// Register parsed GPG keys with server.
  Future<void> registerGpgKeys(List<GpgParsedKey> keys);

  /// List registered GPG keys from server.
  Future<GpgKeyListResponse> listGpgKeys();

  /// Delete a GPG key by keygrip.
  Future<void> deleteGpgKey(String keygrip);

  /// Store GPG private key material securely.
  Future<void> storeGpgPrivateKey(String keygrip, Uint8List material);

  /// Check if GPG private key material exists.
  Future<bool> hasGpgPrivateKey(String keygrip);

  /// Delete stored GPG private key material.
  Future<void> deleteGpgPrivateKeyMaterial(String keygrip);
}
