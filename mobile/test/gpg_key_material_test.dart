import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/security/gpg_key_material.dart';
import 'package:gpg_bridge_mobile/security/gpg_key_models.dart';
import 'package:gpg_bridge_mobile/security/gpg_packet.dart';

void main() {
  group('readMpi', () {
    test('reads MPI with value 0x100 (9 bits)', () {
      // bit count = 9, byte count = 2, bytes = [0x01, 0x00]
      final data = Uint8List.fromList([0x00, 0x09, 0x01, 0x00]);

      final (value, newOffset) = readMpi(data, 0);

      expect(value, BigInt.from(0x100));
      expect(newOffset, 4);
    });

    test('reads MPI with value 65537 (17 bits)', () {
      // bit count = 17, byte count = 3, bytes = [0x01, 0x00, 0x01]
      final data = Uint8List.fromList([0x00, 0x11, 0x01, 0x00, 0x01]);

      final (value, newOffset) = readMpi(data, 0);

      expect(value, BigInt.from(65537));
      expect(newOffset, 5);
    });

    test('reads MPI at non-zero offset', () {
      final data = Uint8List.fromList([0xFF, 0xFF, 0x00, 0x08, 0x42]);

      final (value, newOffset) = readMpi(data, 2);

      expect(value, BigInt.from(0x42));
      expect(newOffset, 5);
    });

    test('throws FormatException when data truncated for length', () {
      final data = Uint8List.fromList([0x00]);

      expect(() => readMpi(data, 0), throwsA(isA<FormatException>()));
    });

    test('throws FormatException when MPI data truncated', () {
      // Claims 16 bits (2 bytes) but only 1 byte available
      final data = Uint8List.fromList([0x00, 0x10, 0x01]);

      expect(() => readMpi(data, 0), throwsA(isA<FormatException>()));
    });
  });

  group('readMpiBytes', () {
    test('returns raw bytes for MPI', () {
      // bit count = 9, byte count = 2, bytes = [0x01, 0x00]
      final data = Uint8List.fromList([0x00, 0x09, 0x01, 0x00]);

      final (bytes, newOffset) = readMpiBytes(data, 0);

      expect(bytes, equals([0x01, 0x00]));
      expect(newOffset, 4);
    });

    test('throws FormatException on truncated data', () {
      final data = Uint8List.fromList([0x00, 0x10, 0x01]);

      expect(() => readMpiBytes(data, 0), throwsA(isA<FormatException>()));
    });
  });

  group('readOid', () {
    test('reads valid OID', () {
      // Length = 3, OID bytes = [0x2A, 0x86, 0x48]
      final data = Uint8List.fromList([0x03, 0x2A, 0x86, 0x48]);

      final (oid, newOffset) = readOid(data, 0);

      expect(oid, equals([0x2A, 0x86, 0x48]));
      expect(newOffset, 4);
    });

    test('reads OID at non-zero offset', () {
      final data = Uint8List.fromList([0xFF, 0x02, 0xAA, 0xBB]);

      final (oid, newOffset) = readOid(data, 1);

      expect(oid, equals([0xAA, 0xBB]));
      expect(newOffset, 4);
    });

    test('throws FormatException when OID data truncated', () {
      // Claims length 5 but only 2 bytes available
      final data = Uint8List.fromList([0x05, 0x01, 0x02]);

      expect(() => readOid(data, 0), throwsA(isA<FormatException>()));
    });

    test('throws FormatException past end of data', () {
      final data = Uint8List.fromList([0x01]);

      expect(() => readOid(data, 1), throwsA(isA<FormatException>()));
    });
  });

  group('extractKeyMaterial', () {
    test('extracts V4 RSA public key material', () {
      // version=4, creation=0, algorithm=1 (RSA)
      // MPI n: value 256 = 0x100, 9 bits → [0x00, 0x09, 0x01, 0x00]
      // MPI e: value 65537 = 0x10001, 17 bits → [0x00, 0x11, 0x01, 0x00, 0x01]
      final body = Uint8List.fromList([
        0x04, // version 4
        0x00, 0x00, 0x00, 0x00, // creation time
        0x01, // RSA algorithm
        0x00, 0x09, 0x01, 0x00, // MPI n = 256
        0x00, 0x11, 0x01, 0x00, 0x01, // MPI e = 65537
      ]);

      final material = extractKeyMaterial(body, PacketTag.publicKey);

      expect(material.version, 4);
      expect(material.creationTime, 0);
      expect(material.algorithm, GpgKeyAlgorithm.rsa);
      expect(material.params['n'], BigInt.from(256));
      expect(material.params['e'], BigInt.from(65537));
    });

    test('extracts V4 ECDSA public key material', () {
      // P-256 OID = 2a8648ce3d030107 (8 bytes)
      const oidBytes = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
      // Uncompressed point: 0x04 + 32 bytes x + 32 bytes y = 65 bytes
      final qBytes = [0x04, ...List<int>.filled(64, 0x42)];
      // MPI for q: bit count = 65 * 8 = 520
      final qMpi = [
        (520 >> 8) & 0xFF, // 0x02
        520 & 0xFF, // 0x08
        ...qBytes,
      ];

      final body = Uint8List.fromList([
        0x04, // version 4
        0x60, 0x00, 0x00, 0x00, // creation time
        19, // ECDSA algorithm
        8, // OID length
        ...oidBytes,
        ...qMpi,
      ]);

      final material = extractKeyMaterial(body, PacketTag.publicKey);

      expect(material.algorithm, GpgKeyAlgorithm.ecdsa);
      expect(material.params['oidName'], 'P-256');
      expect((material.params['q'] as Uint8List).length, 65);
    });

    test('throws FormatException for unsupported version', () {
      final body = Uint8List.fromList([
        0x03, // version 3 — unsupported
        0x00, 0x00, 0x00, 0x00,
        0x01, // RSA
      ]);

      expect(
        () => extractKeyMaterial(body, PacketTag.publicKey),
        throwsA(isA<FormatException>()),
      );
    });

    test('throws FormatException for empty body', () {
      expect(
        () => extractKeyMaterial(Uint8List(0), PacketTag.publicKey),
        throwsA(isA<FormatException>()),
      );
    });

    test('throws FormatException for unsupported algorithm', () {
      final body = Uint8List.fromList([
        0x04, // version 4
        0x00, 0x00, 0x00, 0x00,
        17, // DSA — not implemented for extraction
      ]);

      expect(
        () => extractKeyMaterial(body, PacketTag.publicKey),
        throwsA(isA<FormatException>()),
      );
    });

    test('extracts secret key material for secret key tag', () {
      // RSA public key + trailing secret material bytes
      final body = Uint8List.fromList([
        0x04, // version 4
        0x00, 0x00, 0x00, 0x00,
        0x01, // RSA
        0x00, 0x09, 0x01, 0x00, // MPI n
        0x00, 0x11, 0x01, 0x00, 0x01, // MPI e
        0xDE, 0xAD, // secret material
      ]);

      final material = extractKeyMaterial(body, PacketTag.secretKey);

      expect(material.params['secretMaterial'], isNotNull);
      expect(material.params['secretMaterial'], equals([0xDE, 0xAD]));
    });
  });

  group('ecOidNames', () {
    test('contains known curves', () {
      expect(ecOidNames['2a8648ce3d030107'], 'P-256');
      expect(ecOidNames['2b81040022'], 'P-384');
      expect(ecOidNames['2b81040023'], 'P-521');
      expect(ecOidNames['2b06010401da470f01'], 'Ed25519');
      expect(ecOidNames['2b060104019755010501'], 'Curve25519');
    });
  });
}
