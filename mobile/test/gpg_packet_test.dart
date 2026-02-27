import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/security/gpg_packet.dart';

void main() {
  group('parsePackets', () {
    test('parses single old-format packet with 1-byte length', () {
      // Old format, tag 6 (public key): 0x80 | (6 << 2) | 0 = 0x98
      // 1-byte length = 3, body = [0xAA, 0xBB, 0xCC]
      final data = Uint8List.fromList([0x98, 0x03, 0xAA, 0xBB, 0xCC]);

      final packets = parsePackets(data);

      expect(packets, hasLength(1));
      expect(packets[0].tag, PacketTag.publicKey);
      expect(packets[0].body, equals([0xAA, 0xBB, 0xCC]));
    });

    test('parses single new-format packet with 1-byte length', () {
      // New format, tag 5 (secret key): 0xC0 | 5 = 0xC5
      // 1-byte length = 2, body = [0x11, 0x22]
      final data = Uint8List.fromList([0xC5, 0x02, 0x11, 0x22]);

      final packets = parsePackets(data);

      expect(packets, hasLength(1));
      expect(packets[0].tag, PacketTag.secretKey);
      expect(packets[0].body, equals([0x11, 0x22]));
    });

    test('parses multiple packets in sequence', () {
      // Packet 1: old format public key (tag 6), 1-byte len=1, body=[0x01]
      // Packet 2: old format user id (tag 13), 1-byte len=2, body=[0x41,0x42]
      // Tag 13: 0x80 | (13 << 2) | 0 = 0xB4
      final data = Uint8List.fromList([
        0x98, 0x01, 0x01, // public key
        0xB4, 0x02, 0x41, 0x42, // user id "AB"
      ]);

      final packets = parsePackets(data);

      expect(packets, hasLength(2));
      expect(packets[0].tag, PacketTag.publicKey);
      expect(packets[0].body, equals([0x01]));
      expect(packets[1].tag, PacketTag.userId);
      expect(packets[1].body, equals([0x41, 0x42]));
    });

    test('parses old-format packet with 2-byte length', () {
      // Old format, tag 6, length type 1 (2-byte): 0x80 | (6 << 2) | 1 = 0x99
      // 2-byte length = 0x0003 = 3, body = [0x01, 0x02, 0x03]
      final data = Uint8List.fromList([0x99, 0x00, 0x03, 0x01, 0x02, 0x03]);

      final packets = parsePackets(data);

      expect(packets, hasLength(1));
      expect(packets[0].tag, PacketTag.publicKey);
      expect(packets[0].body, equals([0x01, 0x02, 0x03]));
    });

    test('parses old-format packet with 4-byte length', () {
      // Old format, tag 6, length type 2 (4-byte): 0x80 | (6 << 2) | 2 = 0x9A
      // 4-byte length = 0x00000002, body = [0xFE, 0xFD]
      final data = Uint8List.fromList([
        0x9A,
        0x00,
        0x00,
        0x00,
        0x02,
        0xFE,
        0xFD,
      ]);

      final packets = parsePackets(data);

      expect(packets, hasLength(1));
      expect(packets[0].tag, PacketTag.publicKey);
      expect(packets[0].body, equals([0xFE, 0xFD]));
    });

    test('throws FormatException when bit 7 not set', () {
      // First byte 0x00 has bit 7 = 0 → invalid
      final data = Uint8List.fromList([0x00, 0x01, 0xFF]);

      expect(() => parsePackets(data), throwsA(isA<FormatException>()));
    });

    test('silently skips unknown tag values', () {
      // Old format, tag 15 (unknown): 0x80 | (15 << 2) | 0 = 0xBC
      // 1-byte length = 1, body = [0xFF]
      final data = Uint8List.fromList([0xBC, 0x01, 0xFF]);

      final packets = parsePackets(data);

      expect(packets, isEmpty);
    });

    test('returns empty list for empty input', () {
      final packets = parsePackets(Uint8List(0));

      expect(packets, isEmpty);
    });

    test('parses new-format packet with 2-byte length', () {
      // New format, tag 6 (public key): 0xC0 | 6 = 0xC6
      // 2-byte length encoding: first byte ∈ [192, 223]
      // length = (first - 192) << 8 + second + 192
      // For length 200: (200-192) = 8 → first = 200, but
      // let's use: first = 192, second = 8 → length = (0 << 8) + 8 + 192 = 200
      // Actually let's pick a smaller length we can construct:
      // first = 192, second = 0 → length = (0 << 8) + 0 + 192 = 192
      final body = List<int>.filled(192, 0x42);
      final data = Uint8List.fromList([0xC6, 192, 0, ...body]);

      final packets = parsePackets(data);

      expect(packets, hasLength(1));
      expect(packets[0].tag, PacketTag.publicKey);
      expect(packets[0].body.length, 192);
    });

    test('parses public subkey tag', () {
      // Old format, tag 14 (public subkey): 0x80 | (14 << 2) | 0 = 0xB8
      final data = Uint8List.fromList([0xB8, 0x01, 0xAA]);

      final packets = parsePackets(data);

      expect(packets, hasLength(1));
      expect(packets[0].tag, PacketTag.publicSubkey);
      expect(packets[0].body, equals([0xAA]));
    });

    test('parses secret subkey tag', () {
      // New format, tag 7 (secret subkey): 0xC0 | 7 = 0xC7
      final data = Uint8List.fromList([0xC7, 0x02, 0x11, 0x22]);

      final packets = parsePackets(data);

      expect(packets, hasLength(1));
      expect(packets[0].tag, PacketTag.secretSubkey);
      expect(packets[0].body, equals([0x11, 0x22]));
    });
  });

  group('PacketTag', () {
    test('fromValue returns correct tag', () {
      expect(PacketTag.fromValue(6), PacketTag.publicKey);
      expect(PacketTag.fromValue(5), PacketTag.secretKey);
      expect(PacketTag.fromValue(14), PacketTag.publicSubkey);
      expect(PacketTag.fromValue(2), PacketTag.signature);
    });

    test('fromValue returns null for unknown value', () {
      expect(PacketTag.fromValue(99), isNull);
      expect(PacketTag.fromValue(0), isNull);
    });
  });
}
