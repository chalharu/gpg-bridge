import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import 'gpg_key_models.dart';

/// Computes the libgcrypt-style keygrip for a given key.
///
/// The keygrip is the SHA-1 hash of a canonical S-expression representing
/// the public key parameters, returned as a 40-character uppercase hex string.
///
/// Supported algorithms: RSA, ECDSA, EdDSA, ECDH.
String computeKeygrip(GpgKeyAlgorithm algorithm, Map<String, dynamic> params) {
  final sexp = _buildKeygripSexp(algorithm, params);
  final digest = SHA1Digest();
  final hash = Uint8List(digest.digestSize);
  digest.update(sexp, 0, sexp.length);
  digest.doFinal(hash, 0);
  return hash
      .map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join()
      .toUpperCase();
}

/// Builds the canonical S-expression bytes for keygrip computation.
Uint8List _buildKeygripSexp(
  GpgKeyAlgorithm algorithm,
  Map<String, dynamic> params,
) {
  switch (algorithm) {
    case GpgKeyAlgorithm.rsa:
    case GpgKeyAlgorithm.rsaEncryptOnly:
    case GpgKeyAlgorithm.rsaSignOnly:
      return _buildRsaSexp(params);
    case GpgKeyAlgorithm.ecdsa:
    case GpgKeyAlgorithm.eddsa:
    case GpgKeyAlgorithm.ecdh:
      return _buildEccSexp(params);
    default:
      throw FormatException('keygrip computation not supported for $algorithm');
  }
}

/// Builds RSA keygrip S-expression:
/// `(public-key(rsa(n #HEX#)(e #HEX#)))`
Uint8List _buildRsaSexp(Map<String, dynamic> params) {
  final n = params['n'] as BigInt;
  final e = params['e'] as BigInt;
  return _encodeSexp([
    'public-key',
    [
      'rsa',
      ['n', _bigIntToHashBytes(n)],
      ['e', _bigIntToHashBytes(e)],
    ],
  ]);
}

/// Builds ECC keygrip S-expression:
/// `(public-key(ecc(curve CURVENAME)(q #HEX#)))`
Uint8List _buildEccSexp(Map<String, dynamic> params) {
  final curveName = params['oidName'] as String;
  final q = params['q'] as Uint8List;
  final curveNameForGcrypt = _gcryptCurveName(curveName);
  return _encodeSexp([
    'public-key',
    [
      'ecc',
      ['curve', curveNameForGcrypt],
      ['q', _rawHashBytes(q)],
    ],
  ]);
}

/// Maps curve names to libgcrypt canonical names.
String _gcryptCurveName(String name) {
  const mapping = {
    'P-256': 'NIST P-256',
    'P-384': 'NIST P-384',
    'P-521': 'NIST P-521',
    'Ed25519': 'Ed25519',
    'Curve25519': 'Curve25519',
  };
  return mapping[name] ?? name;
}

/// Encodes a canonical S-expression.
///
/// Elements can be:
/// - [String]: encoded as `length:string`
/// - [List]: encoded as `(` + encoded elements + `)`
/// - [_HashBytes]: encoded as raw byte value with length prefix
Uint8List _encodeSexp(dynamic element) {
  final buf = BytesBuilder();
  _encodeSexpInto(buf, element);
  return buf.toBytes();
}

void _encodeSexpInto(BytesBuilder buf, dynamic element) {
  if (element is _HashBytes) {
    // Must be checked before List since _HashBytes wraps Uint8List.
    final data = element.data;
    buf.add(utf8.encode('${data.length}:'));
    buf.add(data);
  } else if (element is Uint8List) {
    // Must be checked before List since Uint8List extends List<int>.
    buf.add(utf8.encode('${element.length}:'));
    buf.add(element);
  } else if (element is String) {
    final bytes = utf8.encode(element);
    buf.add(utf8.encode('${bytes.length}:'));
    buf.add(bytes);
  } else if (element is List) {
    buf.addByte(0x28); // '('
    for (final child in element) {
      _encodeSexpInto(buf, child);
    }
    buf.addByte(0x29); // ')'
  }
}

/// Converts a [BigInt] to raw bytes for S-expression `#HEX#` encoding.
///
/// Preserves leading zero byte if the high bit is set (unsigned encoding).
Uint8List _bigIntToHashBytes(BigInt value) {
  if (value == BigInt.zero) return Uint8List.fromList([0]);
  final hex = value.toRadixString(16);
  final padded = hex.length.isOdd ? '0$hex' : hex;
  final bytes = Uint8List(padded.length ~/ 2);
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = int.parse(padded.substring(i * 2, i * 2 + 2), radix: 16);
  }
  // Add leading zero if high bit is set (unsigned representation).
  if (bytes[0] & 0x80 != 0) {
    final withZero = Uint8List(bytes.length + 1);
    withZero.setRange(1, withZero.length, bytes);
    return withZero;
  }
  return bytes;
}

/// Wraps raw bytes for S-expression encoding.
_HashBytes _rawHashBytes(Uint8List data) => _HashBytes(data);

class _HashBytes {
  _HashBytes(this.data);
  final Uint8List data;
}
