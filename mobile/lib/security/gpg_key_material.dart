import 'dart:typed_data';

import 'gpg_key_models.dart';
import 'gpg_packet.dart';

/// Well-known EC OID byte sequences and their human-readable names.
const Map<String, String> ecOidNames = {
  '2a8648ce3d030107': 'P-256',
  '2b81040022': 'P-384',
  '2b81040023': 'P-521',
  '2b06010401da470f01': 'Ed25519',
  '2b060104019755010501': 'Curve25519',
};

/// Parsed key material from an OpenPGP key packet.
class GpgKeyMaterial {
  /// Creates parsed key material.
  GpgKeyMaterial({
    required this.version,
    required this.creationTime,
    required this.algorithm,
    required this.params,
  });

  /// Key packet version (typically 4).
  final int version;

  /// Creation time as Unix timestamp.
  final int creationTime;

  /// The public-key algorithm.
  final GpgKeyAlgorithm algorithm;

  /// Algorithm-specific parameters.
  ///
  /// Keys depend on algorithm:
  /// - RSA: `n` ([BigInt]), `e` ([BigInt])
  /// - ECDSA/EdDSA: `oid` ([Uint8List]), `oidName` ([String]),
  ///   `q` ([Uint8List])
  /// - ECDH: same as ECDSA plus `kdfParams` ([Uint8List])
  final Map<String, dynamic> params;
}

/// Reads a multi-precision integer (MPI) from [data] at [offset].
///
/// MPI format: 2-byte big-endian bit count followed by
/// `ceil(bits / 8)` bytes of the value.
///
/// Returns the parsed [BigInt] value and the new offset.
(BigInt value, int newOffset) readMpi(Uint8List data, int offset) {
  if (offset + 2 > data.length) {
    throw const FormatException('unexpected end of data reading MPI length');
  }
  final bitCount = (data[offset] << 8) | data[offset + 1];
  final byteCount = (bitCount + 7) >> 3;
  final end = offset + 2 + byteCount;
  if (end > data.length) {
    throw FormatException('MPI data truncated at offset $offset');
  }
  var value = BigInt.zero;
  for (var i = offset + 2; i < end; i++) {
    value = (value << 8) | BigInt.from(data[i]);
  }
  return (value, end);
}

/// Reads raw MPI bytes (without converting to BigInt) from [data] at
/// [offset]. Returns the raw bytes and the new offset.
(Uint8List bytes, int newOffset) readMpiBytes(Uint8List data, int offset) {
  if (offset + 2 > data.length) {
    throw const FormatException('unexpected end of data reading MPI length');
  }
  final bitCount = (data[offset] << 8) | data[offset + 1];
  final byteCount = (bitCount + 7) >> 3;
  final end = offset + 2 + byteCount;
  if (end > data.length) {
    throw FormatException('MPI bytes truncated at offset $offset');
  }
  return (Uint8List.sublistView(data, offset + 2, end), end);
}

/// Reads an OID from [data] at [offset].
///
/// Format: 1-byte length followed by the OID bytes.
///
/// Returns the OID bytes and the new offset.
(Uint8List oid, int newOffset) readOid(Uint8List data, int offset) {
  if (offset >= data.length) {
    throw const FormatException('unexpected end of data reading OID length');
  }
  final length = data[offset];
  final end = offset + 1 + length;
  if (end > data.length) {
    throw FormatException('OID data truncated at offset $offset');
  }
  return (Uint8List.sublistView(data, offset + 1, end), end);
}

/// Extracts key material from a public or secret key packet [body].
///
/// The [tag] determines whether secret key fields are expected.
/// Only V4 keys are supported; throws [FormatException] otherwise.
GpgKeyMaterial extractKeyMaterial(Uint8List body, PacketTag tag) {
  if (body.isEmpty) {
    throw const FormatException('empty key packet body');
  }
  final version = body[0];
  if (version != 4) {
    throw FormatException('unsupported key version: $version');
  }

  final creationTime =
      (body[1] << 24) | (body[2] << 16) | (body[3] << 8) | body[4];
  final algoId = body[5];
  final algorithm = GpgKeyAlgorithm.fromValue(algoId);
  if (algorithm == null) {
    throw FormatException('unsupported key algorithm: $algoId');
  }

  final params = <String, dynamic>{};
  var offset = 6;

  switch (algorithm) {
    case GpgKeyAlgorithm.rsa:
    case GpgKeyAlgorithm.rsaEncryptOnly:
    case GpgKeyAlgorithm.rsaSignOnly:
      offset = _parseRsaPublic(body, offset, params);
    case GpgKeyAlgorithm.ecdsa:
    case GpgKeyAlgorithm.eddsa:
      offset = _parseEcPublic(body, offset, params);
    case GpgKeyAlgorithm.ecdh:
      offset = _parseEcdhPublic(body, offset, params);
    default:
      throw FormatException(
        'key material extraction not implemented for $algorithm',
      );
  }

  // If it's a secret key packet, store remaining secret material.
  final isSecret = tag == PacketTag.secretKey || tag == PacketTag.secretSubkey;
  if (isSecret && offset < body.length) {
    params['secretMaterial'] = Uint8List.sublistView(body, offset, body.length);
  }

  return GpgKeyMaterial(
    version: version,
    creationTime: creationTime,
    algorithm: algorithm,
    params: params,
  );
}

/// Parses RSA public key fields (MPI n, MPI e).
int _parseRsaPublic(Uint8List body, int offset, Map<String, dynamic> params) {
  final (n, afterN) = readMpi(body, offset);
  params['n'] = n;
  final (e, afterE) = readMpi(body, afterN);
  params['e'] = e;
  return afterE;
}

/// Parses ECDSA / EdDSA public key fields (OID + MPI q).
int _parseEcPublic(Uint8List body, int offset, Map<String, dynamic> params) {
  final (oid, afterOid) = readOid(body, offset);
  params['oid'] = oid;
  params['oidName'] = _resolveOidName(oid);
  final (q, afterQ) = readMpiBytes(body, afterOid);
  params['q'] = q;
  return afterQ;
}

/// Parses ECDH public key fields (OID + MPI q + KDF params).
int _parseEcdhPublic(Uint8List body, int offset, Map<String, dynamic> params) {
  final afterQ = _parseEcPublic(body, offset, params);
  // KDF parameters: 1-byte length + bytes.
  if (afterQ >= body.length) return afterQ;
  final kdfLen = body[afterQ];
  final kdfEnd = afterQ + 1 + kdfLen;
  if (kdfEnd > body.length) {
    throw FormatException('KDF params truncated at offset $afterQ');
  }
  params['kdfParams'] = Uint8List.sublistView(body, afterQ + 1, kdfEnd);
  return kdfEnd;
}

/// Resolves an OID byte sequence to a human-readable curve name.
String _resolveOidName(Uint8List oid) {
  final hex = oid.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  return ecOidNames[hex] ?? 'unknown($hex)';
}
