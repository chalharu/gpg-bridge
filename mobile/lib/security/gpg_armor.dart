import 'dart:convert';
import 'dart:typed_data';

/// CRC24 initial value per RFC 4880 §6.1.
const int _crc24Init = 0xB704CE;

/// CRC24 polynomial per RFC 4880 §6.1.
const int _crc24Poly = 0x1864CFB;

/// Computes CRC-24 checksum per RFC 4880 §6.1.
int _crc24(Uint8List data) {
  var crc = _crc24Init;
  for (final byte in data) {
    crc ^= byte << 16;
    for (var i = 0; i < 8; i++) {
      crc <<= 1;
      if (crc & 0x1000000 != 0) {
        crc ^= _crc24Poly;
      }
    }
  }
  return crc & 0xFFFFFF;
}

/// Decodes an ASCII-armored PGP block into raw binary data.
///
/// Supports both `BEGIN PGP PUBLIC KEY BLOCK` and
/// `BEGIN PGP PRIVATE KEY BLOCK` armor types.
/// Strips metadata headers, validates optional CRC24 checksum,
/// and decodes the base64 payload.
///
/// Throws [FormatException] on invalid input.
Uint8List decodeAsciiArmor(String armored) {
  final lines = armored.split(RegExp(r'\r?\n'));

  final startIdx = lines.indexWhere(
    (l) => l.startsWith('-----BEGIN PGP ') && l.endsWith('-----'),
  );
  if (startIdx < 0) {
    throw const FormatException('missing ASCII armor header');
  }

  final endIdx = lines.indexWhere(
    (l) => l.startsWith('-----END PGP ') && l.endsWith('-----'),
    startIdx + 1,
  );
  if (endIdx < 0) {
    throw const FormatException('missing ASCII armor footer');
  }

  // Skip header line, then skip metadata headers until blank line.
  var bodyStart = startIdx + 1;
  while (bodyStart < endIdx && lines[bodyStart].trim().isNotEmpty) {
    if (!lines[bodyStart].contains(':')) break;
    bodyStart++;
  }
  // Skip the blank separator line.
  if (bodyStart < endIdx && lines[bodyStart].trim().isEmpty) {
    bodyStart++;
  }

  final bodyLines = lines.sublist(bodyStart, endIdx);

  // Separate optional CRC line (starts with '=').
  String? crcLine;
  final base64Lines = <String>[];
  for (final line in bodyLines) {
    if (line.startsWith('=') && line.length == 5) {
      crcLine = line;
    } else {
      base64Lines.add(line.trim());
    }
  }

  final payload = base64.decode(base64Lines.join());
  final result = Uint8List.fromList(payload);

  if (crcLine != null) {
    final crcBytes = base64.decode(crcLine.substring(1));
    final expected = (crcBytes[0] << 16) | (crcBytes[1] << 8) | crcBytes[2];
    final actual = _crc24(result);
    if (actual != expected) {
      throw FormatException(
        'CRC24 mismatch: expected ${expected.toRadixString(16)}, '
        'got ${actual.toRadixString(16)}',
      );
    }
  }

  return result;
}
