import 'dart:typed_data';
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/http/gpg_key_api_service.dart';
import 'package:gpg_bridge_mobile/http/public_key_api_service.dart';
import 'package:gpg_bridge_mobile/pages/keys/gpg_key_import_page.dart';
import 'package:gpg_bridge_mobile/security/gpg_key_models.dart';
import 'package:gpg_bridge_mobile/state/key_management_service.dart';

void main() {
  group('GpgKeyImportPage', () {
    testWidgets('shows validation error when armored key is empty', (
      tester,
    ) async {
      final service = _TrackingKeyManagementService();

      await tester.pumpWidget(_buildDirectApp(service));

      await tester.tap(find.text('解析'));
      await tester.pump();

      expect(find.text('アーマードキーを入力してください'), findsOneWidget);
      expect(service.parsedInputs, isEmpty);
    });

    testWidgets('shows parse error when parser returns no keys', (
      tester,
    ) async {
      final service = _TrackingKeyManagementService();

      await tester.pumpWidget(_buildDirectApp(service));

      await tester.enterText(find.byType(TextField), 'armored-key');
      await tester.tap(find.text('解析'));
      await tester.pump();

      expect(find.text('有効な鍵が見つかりませんでした'), findsOneWidget);
      expect(service.parsedInputs, ['armored-key']);
      expect(find.text('インポート (0件)'), findsNothing);
    });

    testWidgets('shows parse failure when parser throws', (tester) async {
      final service = _TrackingKeyManagementService(
        parseException: Exception('broken armor'),
      );

      await tester.pumpWidget(_buildDirectApp(service));

      await tester.enterText(find.byType(TextField), 'armored-key');
      await tester.tap(find.text('解析'));
      await tester.pump();

      expect(find.textContaining('解析に失敗しました:'), findsOneWidget);
      expect(find.textContaining('broken armor'), findsOneWidget);
    });

    testWidgets('renders primary and subkey preview then imports keys', (
      tester,
    ) async {
      final service = _TrackingKeyManagementService(
        parsedKeys: [
          GpgParsedKey(
            keygrip: 'A' * 40,
            keyId: 'B' * 16,
            publicKeyJwk: const {'kty': 'RSA'},
            algorithm: GpgKeyAlgorithm.rsa,
            isSubkey: false,
            secretKeyMaterial: Uint8List.fromList([1, 2, 3]),
          ),
          GpgParsedKey(
            keygrip: 'C' * 40,
            keyId: 'D' * 16,
            publicKeyJwk: const {'kty': 'EC'},
            algorithm: GpgKeyAlgorithm.ecdsa,
            isSubkey: true,
          ),
        ],
      );

      await tester.pumpWidget(_buildPushApp(service));

      await tester.tap(find.text('open'));
      await tester.pumpAndSettle();

      await tester.enterText(find.byType(TextField), '  armored-key  ');
      await tester.tap(find.text('解析'));
      await tester.pumpAndSettle();

      expect(service.parsedInputs, ['armored-key']);
      expect(find.text('rsa  (主キー)'), findsOneWidget);
      expect(find.text('ecdsa  (サブキー)'), findsOneWidget);
      expect(find.text('秘密鍵あり'), findsOneWidget);
      expect(find.text('Key ID: ${'B' * 16}'), findsOneWidget);
      expect(find.text('Key ID: ${'D' * 16}'), findsOneWidget);
      expect(find.text('インポート (2件)'), findsOneWidget);

      await tester.ensureVisible(find.text('インポート (2件)'));
      await tester.tap(find.text('インポート (2件)'));
      await tester.pumpAndSettle();

      expect(find.text('open'), findsOneWidget);
      expect(find.text('2件の鍵をインポートしました'), findsOneWidget);
      expect(service.storedPrivateKeys, hasLength(1));
      expect(service.storedPrivateKeys.single.keygrip, 'A' * 40);
      expect(service.registeredKeys, hasLength(2));
      expect(service.deletedPrivateKeyMaterials, isEmpty);
    });

    testWidgets(
      'cleans up stored materials and resets importing on import failure',
      (tester) async {
        final registerGate = Completer<void>();
        final service = _TrackingKeyManagementService(
          parsedKeys: [
            GpgParsedKey(
              keygrip: 'A' * 40,
              keyId: 'B' * 16,
              publicKeyJwk: const {'kty': 'RSA'},
              algorithm: GpgKeyAlgorithm.rsa,
              isSubkey: false,
              secretKeyMaterial: Uint8List.fromList([1, 2, 3]),
            ),
            GpgParsedKey(
              keygrip: 'C' * 40,
              keyId: 'D' * 16,
              publicKeyJwk: const {'kty': 'EC'},
              algorithm: GpgKeyAlgorithm.ecdsa,
              isSubkey: true,
            ),
          ],
          onRegisterGpgKeys: (_) async {
            await registerGate.future;
            throw Exception('backend down');
          },
        );

        await tester.pumpWidget(_buildDirectApp(service));

        await tester.enterText(find.byType(TextField), 'armored-key');
        await tester.tap(find.text('解析'));
        await tester.pumpAndSettle();

        await tester.ensureVisible(find.text('インポート (2件)'));
        await tester.tap(find.text('インポート (2件)'));
        await tester.pump();

        expect(find.byType(CircularProgressIndicator), findsOneWidget);

        registerGate.complete();
        await tester.pumpAndSettle();

        expect(find.byType(CircularProgressIndicator), findsNothing);
        expect(find.textContaining('インポートに失敗しました:'), findsOneWidget);
        expect(find.textContaining('backend down'), findsOneWidget);
        expect(service.storedPrivateKeys, hasLength(1));
        expect(service.deletedPrivateKeyMaterials, ['A' * 40, 'C' * 40]);
        expect(service.registeredKeys, isEmpty);
      },
    );
  });
}

Widget _buildDirectApp(KeyManagementService service) {
  return ProviderScope(
    overrides: [keyManagementProvider.overrideWithValue(service)],
    child: const MaterialApp(home: GpgKeyImportPage()),
  );
}

Widget _buildPushApp(KeyManagementService service) {
  return ProviderScope(
    overrides: [keyManagementProvider.overrideWithValue(service)],
    child: MaterialApp(
      home: Scaffold(
        body: Center(
          child: Builder(
            builder: (context) => ElevatedButton(
              onPressed: () => Navigator.of(context).push(
                MaterialPageRoute<void>(
                  builder: (_) => const GpgKeyImportPage(),
                ),
              ),
              child: const Text('open'),
            ),
          ),
        ),
      ),
    ),
  );
}

class _TrackingKeyManagementService implements KeyManagementService {
  _TrackingKeyManagementService({
    this.parsedKeys = const [],
    this.parseException,
    this.onRegisterGpgKeys,
  });

  final List<GpgParsedKey> parsedKeys;
  final Object? parseException;
  final Future<void> Function(List<GpgParsedKey> keys)? onRegisterGpgKeys;
  final List<String> parsedInputs = [];
  final List<GpgParsedKey> registeredKeys = [];
  final List<_StoredPrivateKey> storedPrivateKeys = [];
  final List<String> deletedPrivateKeyMaterials = [];

  @override
  Future<void> addE2eKeyPair() async {}

  @override
  Future<void> deleteGpgKey(String keygrip) async {}

  @override
  Future<void> deleteGpgPrivateKeyMaterial(String keygrip) async {
    deletedPrivateKeyMaterials.add(keygrip);
  }

  @override
  Future<void> deletePublicKey(String kid) async {}

  @override
  Future<bool> hasGpgPrivateKey(String keygrip) async => false;

  @override
  Future<GpgKeyListResponse> listGpgKeys() async {
    return GpgKeyListResponse(gpgKeys: const []);
  }

  @override
  Future<PublicKeyListResponse> listPublicKeys() async {
    return PublicKeyListResponse(keys: const [], defaultKid: 'none');
  }

  @override
  List<GpgParsedKey> parseGpgArmoredKey(String armoredKey) {
    parsedInputs.add(armoredKey);
    if (parseException != null) {
      throw parseException!;
    }
    return parsedKeys;
  }

  @override
  Future<Uint8List?> readGpgPrivateKey(String keygrip) async => null;

  @override
  Future<void> registerGpgKeys(List<GpgParsedKey> keys) async {
    if (onRegisterGpgKeys != null) {
      await onRegisterGpgKeys!(keys);
    }
    registeredKeys.addAll(keys);
  }

  @override
  Future<void> storeGpgPrivateKey(String keygrip, Uint8List material) async {
    storedPrivateKeys.add(_StoredPrivateKey(keygrip, material));
  }
}

class _StoredPrivateKey {
  _StoredPrivateKey(this.keygrip, this.material);

  final String keygrip;
  final Uint8List material;
}
