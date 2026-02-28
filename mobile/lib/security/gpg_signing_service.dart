import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import 'crypto_utils.dart' show base64UrlDecode, bytesToBigInt;
import 'gpg_key_material.dart' show readMpi;

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
        'RSA' => _signRsa(
          hashBytes,
          hashAlgorithm,
          secretMaterial,
          publicKeyJwk,
        ),
        'EC' => _signEcdsa(hashBytes, secretMaterial, publicKeyJwk),
        _ => null, // OKP (Ed25519) and others unsupported
      };
    } catch (e) {
      if (e is GpgSigningException) rethrow;
      throw GpgSigningException('signing failed', cause: e);
    }
  }
}

// ---------------------------------------------------------------------------
// RSA PKCS#1 v1.5
// ---------------------------------------------------------------------------

Uint8List _signRsa(
  Uint8List hashBytes,
  String hashAlgorithm,
  Uint8List secretMaterial,
  Map<String, dynamic> jwk,
) {
  final n = _jwkParamToBigInt(jwk, 'n');
  final (d, p, q) = _parseRsaSecret(secretMaterial);
  final privKey = RSAPrivateKey(n, d, p, q);

  try {
    final digestInfo = _buildDigestInfo(hashAlgorithm, hashBytes);
    final engine = PKCS1Encoding(RSAEngine());
    engine.init(true, PrivateKeyParameter<RSAPrivateKey>(privKey));
    return engine.process(digestInfo);
  } finally {
    _zeroFill(secretMaterial);
  }
}

/// Parses RSA secret MPIs: d, p, q, u (u is discarded).
(BigInt d, BigInt p, BigInt q) _parseRsaSecret(Uint8List data) {
  if (data.isEmpty || data[0] != 0) {
    throw GpgSigningException('encrypted key not supported (S2K != 0)');
  }
  var offset = 1;
  final (d, afterD) = readMpi(data, offset);
  final (p, afterP) = readMpi(data, afterD);
  final (q, afterQ) = readMpi(data, afterP);
  // u (inverse of p mod q) — skip, pointycastle computes internally.
  readMpi(data, afterQ);
  return (d, p, q);
}

/// DigestInfo ASN.1 DER prefixes keyed by OpenPGP hash algorithm name.
const _digestInfoPrefixes = <String, List<int>>{
  'sha256': [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, //
    0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
  ],
  'sha384': [
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, //
    0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
  ],
  'sha512': [
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, //
    0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
  ],
  'sha224': [
    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, //
    0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c,
  ],
  'sha1': [
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, //
    0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
  ],
};

Uint8List _buildDigestInfo(String hashAlgorithm, Uint8List hash) {
  final prefix = _digestInfoPrefixes[hashAlgorithm.toLowerCase()];
  if (prefix == null) {
    throw GpgSigningException('unsupported hash algorithm: $hashAlgorithm');
  }
  return Uint8List.fromList([...prefix, ...hash]);
}

// ---------------------------------------------------------------------------
// ECDSA (P-256 / P-384 / P-521)
// ---------------------------------------------------------------------------

Uint8List _signEcdsa(
  Uint8List hashBytes,
  Uint8List secretMaterial,
  Map<String, dynamic> jwk,
) {
  final crv = jwk['crv'] as String?;
  final (domainName, orderLen) = _ecDomainParams(crv);
  final d = _parseEcdsaSecret(secretMaterial);
  final domain = ECDomainParameters(domainName);
  final privKey = ECPrivateKey(d, domain);

  try {
    final signer = ECDSASigner(null, null);
    signer.init(
      true,
      ParametersWithRandom(
        PrivateKeyParameter<ECPrivateKey>(privKey),
        _newSecureRandom(),
      ),
    );
    final sig = signer.generateSignature(hashBytes) as ECSignature;
    return _encodeRawEcdsaSignature(sig.r, sig.s, orderLen);
  } finally {
    _zeroFill(secretMaterial);
  }
}

/// Maps JWK curve name to pointycastle domain and order byte length.
(String domain, int orderLen) _ecDomainParams(String? crv) {
  return switch (crv) {
    'P-256' => ('secp256r1', 32),
    'P-384' => ('secp384r1', 48),
    'P-521' => ('secp521r1', 66),
    _ => throw GpgSigningException('unsupported EC curve: $crv'),
  };
}

BigInt _parseEcdsaSecret(Uint8List data) {
  if (data.isEmpty || data[0] != 0) {
    throw GpgSigningException('encrypted key not supported (S2K != 0)');
  }
  final (d, _) = readMpi(data, 1);
  return d;
}

/// Encodes R and S as fixed-width big-endian concatenation.
Uint8List _encodeRawEcdsaSignature(BigInt r, BigInt s, int orderLen) {
  final result = Uint8List(orderLen * 2);
  _bigIntToFixed(r, result, 0, orderLen);
  _bigIntToFixed(s, result, orderLen, orderLen);
  return result;
}

void _bigIntToFixed(BigInt value, Uint8List out, int offset, int length) {
  final hex = value.toRadixString(16).padLeft(length * 2, '0');
  for (var i = 0; i < length; i++) {
    out[offset + i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

BigInt _jwkParamToBigInt(Map<String, dynamic> jwk, String key) {
  final encoded = jwk[key] as String?;
  if (encoded == null) {
    throw GpgSigningException('missing JWK parameter: $key');
  }
  return bytesToBigInt(base64UrlDecode(encoded));
}

FortunaRandom _newSecureRandom() {
  final random = FortunaRandom();
  final seed = List<int>.generate(32, (_) => Random.secure().nextInt(256));
  random.seed(KeyParameter(Uint8List.fromList(seed)));
  return random;
}

void _zeroFill(Uint8List data) {
  data.fillRange(0, data.length, 0);
}
