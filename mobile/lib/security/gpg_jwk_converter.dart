import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import 'crypto_utils.dart' show base64UrlEncode;
import 'gpg_key_models.dart';

/// Converts parsed GPG key material parameters to a JWK map.
///
/// Supported algorithms:
/// - RSA → `{kty: "RSA", n, e}`
/// - ECDSA (P-256, P-384, P-521) → `{kty: "EC", crv, x, y}`
/// - EdDSA (Ed25519) → `{kty: "OKP", crv: "Ed25519", x}`
/// - ECDH (Curve25519) → `{kty: "OKP", crv: "X25519", x}`
///
/// Throws [FormatException] for unsupported algorithms or bad data.
Map<String, dynamic> keyMaterialToJwk(
  GpgKeyAlgorithm algorithm,
  Map<String, dynamic> params,
) {
  switch (algorithm) {
    case GpgKeyAlgorithm.rsa:
    case GpgKeyAlgorithm.rsaEncryptOnly:
    case GpgKeyAlgorithm.rsaSignOnly:
      return _rsaToJwk(params);
    case GpgKeyAlgorithm.ecdsa:
      return _ecdsaToJwk(params);
    case GpgKeyAlgorithm.eddsa:
      return _eddsaToJwk(params);
    case GpgKeyAlgorithm.ecdh:
      return _ecdhToJwk(params);
    default:
      throw FormatException('JWK conversion not supported for $algorithm');
  }
}

/// Converts RSA parameters to JWK.
Map<String, dynamic> _rsaToJwk(Map<String, dynamic> params) {
  final n = params['n'] as BigInt;
  final e = params['e'] as BigInt;
  return {
    'kty': 'RSA',
    'n': base64UrlEncode(_bigIntToBytes(n)),
    'e': base64UrlEncode(_bigIntToBytes(e)),
  };
}

/// Converts ECDSA parameters to JWK.
Map<String, dynamic> _ecdsaToJwk(Map<String, dynamic> params) {
  final oidName = params['oidName'] as String;
  final q = params['q'] as Uint8List;
  final (crv, coordLen) = _ecCurveParams(oidName);

  if (q.isEmpty || q[0] != 0x04) {
    throw const FormatException('expected uncompressed EC point (0x04 prefix)');
  }
  if (q.length != 1 + coordLen * 2) {
    throw FormatException('invalid EC point length for $crv: ${q.length}');
  }

  return {
    'kty': 'EC',
    'crv': crv,
    'x': base64UrlEncode(Uint8List.sublistView(q, 1, 1 + coordLen)),
    'y': base64UrlEncode(
      Uint8List.sublistView(q, 1 + coordLen, 1 + coordLen * 2),
    ),
  };
}

/// Converts EdDSA parameters to JWK.
Map<String, dynamic> _eddsaToJwk(Map<String, dynamic> params) {
  final oidName = params['oidName'] as String;
  final q = params['q'] as Uint8List;

  if (oidName != 'Ed25519') {
    throw FormatException('unsupported EdDSA curve: $oidName');
  }
  // OpenPGP prepends 0x40 to the native 32-byte key.
  final rawKey = (q.isNotEmpty && q[0] == 0x40) ? q.sublist(1) : q;
  return {
    'kty': 'OKP',
    'crv': 'Ed25519',
    'x': base64UrlEncode(Uint8List.fromList(rawKey)),
  };
}

/// Converts ECDH parameters to JWK.
Map<String, dynamic> _ecdhToJwk(Map<String, dynamic> params) {
  final oidName = params['oidName'] as String;
  final q = params['q'] as Uint8List;

  if (oidName == 'Curve25519') {
    // OpenPGP prepends 0x40 to the native 32-byte key.
    final rawKey = (q.isNotEmpty && q[0] == 0x40) ? q.sublist(1) : q;
    return {
      'kty': 'OKP',
      'crv': 'X25519',
      'x': base64UrlEncode(Uint8List.fromList(rawKey)),
    };
  }
  // ECDH with NIST curves uses same point format as ECDSA.
  return _ecdsaToJwk(params);
}

/// Returns JWK curve name and coordinate byte length for [oidName].
(String crv, int coordLen) _ecCurveParams(String oidName) {
  return switch (oidName) {
    'P-256' => ('P-256', 32),
    'P-384' => ('P-384', 48),
    'P-521' => ('P-521', 66),
    _ => throw FormatException('unsupported EC curve: $oidName'),
  };
}

/// Computes the V4 key ID from a key packet body.
///
/// V4 fingerprint = SHA-1(0x99 || 2-byte-length || packet body).
/// Key ID = last 8 bytes of the fingerprint, as a hex string.
String computeKeyId(Uint8List packetBody) {
  final length = packetBody.length;
  final hashInput = Uint8List(3 + length);
  hashInput[0] = 0x99;
  hashInput[1] = (length >> 8) & 0xFF;
  hashInput[2] = length & 0xFF;
  hashInput.setRange(3, 3 + length, packetBody);

  final digest = SHA1Digest();
  final hash = Uint8List(digest.digestSize);
  digest.update(hashInput, 0, hashInput.length);
  digest.doFinal(hash, 0);

  // Last 8 bytes = 16 hex characters.
  return hash
      .sublist(hash.length - 8)
      .map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join()
      .toUpperCase();
}

/// Converts a [BigInt] to minimal unsigned big-endian bytes.
Uint8List _bigIntToBytes(BigInt value) {
  if (value == BigInt.zero) return Uint8List.fromList([0]);
  final hex = value.toRadixString(16);
  final padded = hex.length.isOdd ? '0$hex' : hex;
  final bytes = Uint8List(padded.length ~/ 2);
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = int.parse(padded.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return bytes;
}
