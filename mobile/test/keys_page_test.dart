import 'dart:async';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/http/gpg_key_api_service.dart';
import 'package:gpg_bridge_mobile/http/public_key_api_service.dart';
import 'package:gpg_bridge_mobile/pages/keys_page.dart';
import 'package:gpg_bridge_mobile/security/gpg_key_models.dart';
import 'package:gpg_bridge_mobile/state/key_management_service.dart';

// ---------------------------------------------------------------------------
// Mock implementation
// ---------------------------------------------------------------------------

class _MockKeyManagementService implements KeyManagementService {
  _MockKeyManagementService({
    this.publicKeyCompleter,
    this.gpgKeyCompleter,
    this.listPublicKeysHandler,
    this.listGpgKeysHandler,
    this.addE2eKeyPairHandler,
    this.deletePublicKeyHandler,
    this.deleteGpgKeyHandler,
  });

  final Completer<PublicKeyListResponse>? publicKeyCompleter;
  final Completer<GpgKeyListResponse>? gpgKeyCompleter;
  final Future<PublicKeyListResponse> Function()? listPublicKeysHandler;
  final Future<GpgKeyListResponse> Function()? listGpgKeysHandler;
  final Future<void> Function()? addE2eKeyPairHandler;
  final Future<void> Function(String kid)? deletePublicKeyHandler;
  final Future<void> Function(String keygrip)? deleteGpgKeyHandler;

  int addE2eKeyPairCallCount = 0;
  int deletePublicKeyCallCount = 0;
  int deleteGpgKeyCallCount = 0;

  @override
  Future<PublicKeyListResponse> listPublicKeys() {
    if (listPublicKeysHandler != null) return listPublicKeysHandler!();
    if (publicKeyCompleter != null) return publicKeyCompleter!.future;
    return Future.value(PublicKeyListResponse(keys: [], defaultKid: 'none'));
  }

  @override
  Future<GpgKeyListResponse> listGpgKeys() {
    if (listGpgKeysHandler != null) return listGpgKeysHandler!();
    if (gpgKeyCompleter != null) return gpgKeyCompleter!.future;
    return Future.value(GpgKeyListResponse(gpgKeys: []));
  }

  @override
  Future<void> addE2eKeyPair() async {
    addE2eKeyPairCallCount += 1;
    await addE2eKeyPairHandler?.call();
  }

  @override
  Future<void> deletePublicKey(String kid) async {
    deletePublicKeyCallCount += 1;
    await deletePublicKeyHandler?.call(kid);
  }

  @override
  List<GpgParsedKey> parseGpgArmoredKey(String armoredKey) => [];

  @override
  Future<void> registerGpgKeys(List<GpgParsedKey> keys) async {}

  @override
  Future<void> deleteGpgKey(String keygrip) async {
    deleteGpgKeyCallCount += 1;
    await deleteGpgKeyHandler?.call(keygrip);
  }

  @override
  Future<void> storeGpgPrivateKey(String keygrip, Uint8List material) async {}

  @override
  Future<bool> hasGpgPrivateKey(String keygrip) async => false;

  @override
  Future<void> deleteGpgPrivateKeyMaterial(String keygrip) async {}

  @override
  Future<Uint8List?> readGpgPrivateKey(String keygrip) async => null;
}

// ---------------------------------------------------------------------------
// Helper to pump KeysPage inside a ProviderScope + MaterialApp
// ---------------------------------------------------------------------------

Widget _buildTestApp(KeyManagementService mockService) {
  return ProviderScope(
    overrides: [keyManagementProvider.overrideWithValue(mockService)],
    child: const MaterialApp(home: KeysPage()),
  );
}

PublicKeyListResponse _publicKeysResponse({
  required List<Map<String, dynamic>> keys,
}) {
  return PublicKeyListResponse(
    keys: keys,
    defaultKid: keys.firstOrNull?['kid'] as String? ?? 'none',
  );
}

GpgKeyListResponse _gpgKeysResponse({required List<GpgKeyEntry> keys}) {
  return GpgKeyListResponse(gpgKeys: keys);
}

Map<String, dynamic> _publicKey({
  required String kid,
  String use = 'sig',
  String alg = 'ES256',
}) {
  return {'kid': kid, 'use': use, 'alg': alg, 'kty': 'EC'};
}

GpgKeyEntry _gpgKey({required String keygrip, required String keyId}) {
  return GpgKeyEntry(
    keygrip: keygrip,
    keyId: keyId,
    publicKey: const {'kty': 'RSA'},
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

void main() {
  group('KeysPage', () {
    testWidgets('renders with two tabs', (WidgetTester tester) async {
      final mock = _MockKeyManagementService();
      await tester.pumpWidget(_buildTestApp(mock));

      expect(find.text('E2E公開鍵'), findsOneWidget);
      expect(find.text('GPG鍵'), findsOneWidget);
    });

    testWidgets('shows loading indicator initially on E2E tab', (
      WidgetTester tester,
    ) async {
      final mock = _MockKeyManagementService(
        publicKeyCompleter: Completer<PublicKeyListResponse>(),
        gpgKeyCompleter: Completer<GpgKeyListResponse>(),
      );
      await tester.pumpWidget(_buildTestApp(mock));
      await tester.pump();

      expect(find.byType(CircularProgressIndicator), findsOneWidget);
    });

    testWidgets('shows loading indicator initially on GPG tab', (
      WidgetTester tester,
    ) async {
      final mock = _MockKeyManagementService(
        publicKeyCompleter: Completer<PublicKeyListResponse>(),
        gpgKeyCompleter: Completer<GpgKeyListResponse>(),
      );
      await tester.pumpWidget(_buildTestApp(mock));
      await tester.pump();

      await tester.tap(find.text('GPG鍵'));
      await tester.pump();

      expect(find.byType(CircularProgressIndicator), findsOneWidget);
    });

    testWidgets('E2E tab shows empty message after loading', (
      WidgetTester tester,
    ) async {
      final mock = _MockKeyManagementService();
      await tester.pumpWidget(_buildTestApp(mock));
      await tester.pumpAndSettle();

      expect(find.text('登録されている公開鍵はありません'), findsOneWidget);
    });

    testWidgets('GPG tab shows empty message after loading', (
      WidgetTester tester,
    ) async {
      final mock = _MockKeyManagementService();
      await tester.pumpWidget(_buildTestApp(mock));
      await tester.pumpAndSettle();

      await tester.tap(find.text('GPG鍵'));
      await tester.pumpAndSettle();

      expect(find.text('登録されているGPG鍵はありません'), findsOneWidget);
    });

    testWidgets('E2E tab retries after load failure', (
      WidgetTester tester,
    ) async {
      var attempts = 0;
      final mock = _MockKeyManagementService(
        listPublicKeysHandler: () async {
          attempts += 1;
          if (attempts == 1) {
            throw Exception('network down');
          }
          return _publicKeysResponse(
            keys: [
              _publicKey(
                kid: '11111111-1111-1111-1111-111111111111',
                use: 'sig',
                alg: 'ES256',
              ),
            ],
          );
        },
      );

      await tester.pumpWidget(_buildTestApp(mock));
      await tester.pumpAndSettle();

      expect(find.text('読み込みに失敗しました'), findsOneWidget);
      expect(find.textContaining('network down'), findsOneWidget);

      await tester.tap(find.text('再試行'));
      await tester.pump();
      await tester.pumpAndSettle();

      expect(find.text('認証用  ES256'), findsOneWidget);
      expect(attempts, 2);
    });

    testWidgets('E2E tab adds a key pair and reloads the list', (
      WidgetTester tester,
    ) async {
      var created = false;
      final mock = _MockKeyManagementService(
        listPublicKeysHandler: () async {
          if (!created) {
            return _publicKeysResponse(keys: const []);
          }
          return _publicKeysResponse(
            keys: [
              _publicKey(
                kid: '22222222-2222-2222-2222-222222222222',
                use: 'enc',
                alg: 'ECDH-ES+A256KW',
              ),
            ],
          );
        },
        addE2eKeyPairHandler: () async {
          created = true;
        },
      );

      await tester.pumpWidget(_buildTestApp(mock));
      await tester.pumpAndSettle();

      await tester.tap(find.byType(FloatingActionButton));
      await tester.pump();
      await tester.pumpAndSettle();

      expect(mock.addE2eKeyPairCallCount, 1);
      expect(find.text('暗号化用  ECDH-ES+A256KW'), findsOneWidget);
      expect(find.text('鍵ペアを生成しました'), findsOneWidget);
    });

    testWidgets('E2E tab deletes a key after confirmation', (
      WidgetTester tester,
    ) async {
      var deleted = false;
      final mock = _MockKeyManagementService(
        listPublicKeysHandler: () async {
          if (deleted) {
            return _publicKeysResponse(keys: const []);
          }
          return _publicKeysResponse(
            keys: [
              _publicKey(
                kid: '33333333-3333-3333-3333-333333333333',
                use: 'sig',
                alg: 'ES256',
              ),
            ],
          );
        },
        deletePublicKeyHandler: (kid) async {
          deleted = true;
        },
      );

      await tester.pumpWidget(_buildTestApp(mock));
      await tester.pumpAndSettle();

      expect(find.text('認証用  ES256'), findsOneWidget);

      await tester.tap(find.byIcon(Icons.delete));
      await tester.pumpAndSettle();
      await tester.tap(find.text('削除'));
      await tester.pump();
      await tester.pumpAndSettle();

      expect(mock.deletePublicKeyCallCount, 1);
      expect(find.text('登録されている公開鍵はありません'), findsOneWidget);
      expect(find.text('鍵を削除しました'), findsOneWidget);
    });

    testWidgets('GPG tab deletes a key after confirmation', (
      WidgetTester tester,
    ) async {
      var deleted = false;
      final mock = _MockKeyManagementService(
        listGpgKeysHandler: () async {
          if (deleted) {
            return _gpgKeysResponse(keys: const []);
          }
          return _gpgKeysResponse(
            keys: [
              _gpgKey(
                keygrip: '0123456789abcdef0123456789abcdef01234567',
                keyId: 'ABCD1234',
              ),
            ],
          );
        },
        deleteGpgKeyHandler: (keygrip) async {
          deleted = true;
        },
      );

      await tester.pumpWidget(_buildTestApp(mock));
      await tester.pumpAndSettle();
      await tester.tap(find.text('GPG鍵'));
      await tester.pumpAndSettle();

      expect(find.text('Key ID: ABCD1234'), findsOneWidget);

      await tester.tap(find.byIcon(Icons.delete));
      await tester.pumpAndSettle();
      await tester.tap(find.text('削除'));
      await tester.pump();
      await tester.pumpAndSettle();

      expect(mock.deleteGpgKeyCallCount, 1);
      expect(find.text('登録されているGPG鍵はありません'), findsOneWidget);
      expect(find.text('GPG鍵を削除しました'), findsOneWidget);
    });
  });
}
