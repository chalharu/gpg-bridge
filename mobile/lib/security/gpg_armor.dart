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
  final startIdx = _findArmorHeader(lines);
  final endIdx = _findArmorFooter(lines, startIdx);
  final bodyStart = _findArmorBodyStart(lines, startIdx, endIdx);
  final (base64Lines, crcLine) = _splitArmorBody(lines.sublist(bodyStart, endIdx));

  final payload = base64.decode(base64Lines.join());
  final result = Uint8List.fromList(payload);

  _validateCrc24(result, crcLine);

  return result;
}

int _findArmorHeader(List<String> lines) {
  final startIdx = lines.indexWhere(
    (line) => line.startsWith('-----BEGIN PGP ') && line.endsWith('-----'),
  );
  if (startIdx < 0) {
    throw const FormatException('missing ASCII armor header');
  }
  return startIdx;
}

int _findArmorFooter(List<String> lines, int startIdx) {
  final endIdx = lines.indexWhere(
    (line) => line.startsWith('-----END PGP ') && line.endsWith('-----'),
    startIdx + 1,
  );
  if (endIdx < 0) {
    throw const FormatException('missing ASCII armor footer');
  }
  return endIdx;
}

int _findArmorBodyStart(List<String> lines, int startIdx, int endIdx) {
  var bodyStart = startIdx + 1;
  while (bodyStart < endIdx && lines[bodyStart].trim().isNotEmpty) {
    if (!lines[bodyStart].contains(':')) {
      break;
    }
    bodyStart++;
  }
  if (bodyStart < endIdx && lines[bodyStart].trim().isEmpty) {
    bodyStart++;
  }
  return bodyStart;
}

(List<String>, String?) _splitArmorBody(List<String> bodyLines) {
  String? crcLine;
  final base64Lines = <String>[];

  for (final line in bodyLines) {
    if (line.startsWith('=') && line.length == 5) {
      crcLine = line;
      continue;
    }
    base64Lines.add(line.trim());
  }

  return (base64Lines, crcLine);
}

void _validateCrc24(Uint8List payload, String? crcLine) {
  if (crcLine == null) {
    return;
  }

  final crcBytes = base64.decode(crcLine.substring(1));
  final expected = (crcBytes[0] << 16) | (crcBytes[1] << 8) | crcBytes[2];
  final actual = _crc24(payload);
  if (actual != expected) {
    throw FormatException(
      'CRC24 mismatch: expected ${expected.toRadixString(16)}, '
      'got ${actual.toRadixString(16)}',
    );
  }
}
