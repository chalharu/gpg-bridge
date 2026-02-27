import 'dart:typed_data';

/// OpenPGP packet tag values per RFC 4880 §4.3.
enum PacketTag {
  /// Signature packet (tag 2).
  signature(2),

  /// Secret key packet (tag 5).
  secretKey(5),

  /// Public key packet (tag 6).
  publicKey(6),

  /// Secret subkey packet (tag 7).
  secretSubkey(7),

  /// User ID packet (tag 13).
  userId(13),

  /// Public subkey packet (tag 14).
  publicSubkey(14);

  const PacketTag(this.value);

  /// The numeric tag value.
  final int value;

  /// Returns the [PacketTag] for a given numeric [value], or `null` if not
  /// recognized.
  static PacketTag? fromValue(int value) {
    for (final tag in PacketTag.values) {
      if (tag.value == value) return tag;
    }
    return null;
  }
}

/// A single OpenPGP packet with its [tag] and raw [body] bytes.
class GpgPacket {
  /// Creates a packet with the given [tag] and [body].
  GpgPacket({required this.tag, required this.body});

  /// The packet tag identifying the type.
  final PacketTag tag;

  /// The raw body bytes of the packet.
  final Uint8List body;
}

/// Parses OpenPGP packets from raw [data] bytes.
///
/// Supports both old-format and new-format packet headers as described
/// in RFC 4880 §4.2. Unknown tag values are silently skipped.
///
/// Throws [FormatException] on malformed packet headers.
List<GpgPacket> parsePackets(Uint8List data) {
  final packets = <GpgPacket>[];
  var offset = 0;

  while (offset < data.length) {
    final header = data[offset];
    if (header & 0x80 == 0) {
      throw FormatException(
        'invalid packet header at offset $offset: bit 7 not set',
      );
    }

    final isNewFormat = (header & 0x40) != 0;
    int tagValue;
    int bodyLength;
    int bodyStart;

    if (isNewFormat) {
      tagValue = header & 0x3F;
      final parsed = _parseNewFormatLength(data, offset + 1);
      bodyLength = parsed.length;
      bodyStart = parsed.headerEnd;
    } else {
      tagValue = (header >> 2) & 0x0F;
      final lengthType = header & 0x03;
      final parsed = _parseOldFormatLength(data, offset + 1, lengthType);
      bodyLength = parsed.length;
      bodyStart = parsed.headerEnd;
    }

    final tag = PacketTag.fromValue(tagValue);
    if (tag != null) {
      packets.add(
        GpgPacket(
          tag: tag,
          body: Uint8List.sublistView(data, bodyStart, bodyStart + bodyLength),
        ),
      );
    }

    offset = bodyStart + bodyLength;
  }

  return packets;
}

/// Result of parsing a packet length field.
class _LengthResult {
  _LengthResult({required this.length, required this.headerEnd});
  final int length;
  final int headerEnd;
}

/// Parses new-format packet length starting at [offset].
_LengthResult _parseNewFormatLength(Uint8List data, int offset) {
  if (offset >= data.length) {
    throw FormatException('truncated new-format length at offset $offset');
  }
  final first = data[offset];
  if (first < 192) {
    return _LengthResult(length: first, headerEnd: offset + 1);
  }
  if (first < 224) {
    if (offset + 2 > data.length) {
      throw FormatException('truncated 2-byte length at offset $offset');
    }
    final second = data[offset + 1];
    final length = ((first - 192) << 8) + second + 192;
    return _LengthResult(length: length, headerEnd: offset + 2);
  }
  if (first == 255) {
    if (offset + 5 > data.length) {
      throw FormatException('truncated 5-byte length at offset $offset');
    }
    final length =
        (data[offset + 1] << 24) |
        (data[offset + 2] << 16) |
        (data[offset + 3] << 8) |
        data[offset + 4];
    return _LengthResult(length: length, headerEnd: offset + 5);
  }
  // Partial body length — not supported for key packets.
  return _parsePartialBody(data, offset);
}

/// Partial body length is used for streaming packets (encrypted/compressed)
/// and is not expected for key packets. Fail fast rather than silently
/// producing corrupted output.
Never _parsePartialBody(Uint8List data, int offset) {
  throw FormatException(
    'partial body length not supported for key packets at offset $offset',
  );
}

/// Parses old-format packet length starting at [offset] with the given
/// [lengthType] (0–3).
_LengthResult _parseOldFormatLength(
  Uint8List data,
  int offset,
  int lengthType,
) {
  switch (lengthType) {
    case 0:
      if (offset >= data.length) {
        throw FormatException(
          'truncated old-format 1-byte length at offset $offset',
        );
      }
      return _LengthResult(length: data[offset], headerEnd: offset + 1);
    case 1:
      if (offset + 2 > data.length) {
        throw FormatException(
          'truncated old-format 2-byte length at offset $offset',
        );
      }
      final length = (data[offset] << 8) | data[offset + 1];
      return _LengthResult(length: length, headerEnd: offset + 2);
    case 2:
      if (offset + 4 > data.length) {
        throw FormatException(
          'truncated old-format 4-byte length at offset $offset',
        );
      }
      final length =
          (data[offset] << 24) |
          (data[offset + 1] << 16) |
          (data[offset + 2] << 8) |
          data[offset + 3];
      return _LengthResult(length: length, headerEnd: offset + 4);
    case 3:
      // Indeterminate length — body extends to end of data.
      return _LengthResult(length: data.length - offset, headerEnd: offset);
    default:
      throw FormatException('invalid old-format length type: $lengthType');
  }
}
