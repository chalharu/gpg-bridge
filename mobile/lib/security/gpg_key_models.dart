import 'dart:typed_data';

/// OpenPGP public-key algorithm identifiers per RFC 4880 §9.1.
enum GpgKeyAlgorithm {
  /// RSA (Encrypt or Sign).
  rsa(1),

  /// RSA Encrypt-Only (deprecated).
  rsaEncryptOnly(2),

  /// RSA Sign-Only (deprecated).
  rsaSignOnly(3),

  /// Elgamal (Encrypt-Only).
  elgamal(16),

  /// DSA (Digital Signature Algorithm).
  dsa(17),

  /// ECDH (RFC 6637).
  ecdh(18),

  /// ECDSA (RFC 6637).
  ecdsa(19),

  /// EdDSA (legacy, draft-koch-eddsa-for-openpgp).
  eddsa(22),

  /// X25519 (RFC 9580).
  x25519New(25),

  /// X448 (RFC 9580).
  x448New(26),

  /// Ed25519 (RFC 9580).
  eddsaNew(27),

  /// Ed448 (RFC 9580).
  ed448New(28);

  const GpgKeyAlgorithm(this.value);

  /// The numeric algorithm identifier.
  final int value;

  /// Returns the [GpgKeyAlgorithm] for a given numeric [value], or `null`
  /// if the value does not correspond to a known algorithm.
  static GpgKeyAlgorithm? fromValue(int v) {
    for (final algo in GpgKeyAlgorithm.values) {
      if (algo.value == v) return algo;
    }
    return null;
  }
}

/// A fully parsed GPG key with its identifiers and JWK representation.
class GpgParsedKey {
  /// Creates a parsed key entry.
  GpgParsedKey({
    required this.keygrip,
    required this.keyId,
    required this.publicKeyJwk,
    required this.algorithm,
    required this.isSubkey,
    this.secretKeyMaterial,
  });

  /// 40-character hex keygrip (SHA-1 of libgcrypt S-expression).
  final String keygrip;

  /// Hex key ID (last 8 bytes of the V4 fingerprint).
  final String keyId;

  /// JWK representation of the public key.
  final Map<String, dynamic> publicKeyJwk;

  /// The public-key algorithm used by this key.
  final GpgKeyAlgorithm algorithm;

  /// Whether this key is a subkey (as opposed to a primary key).
  final bool isSubkey;

  /// Raw secret-key material bytes, if available.
  final Uint8List? secretKeyMaterial;
}
