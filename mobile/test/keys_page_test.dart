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
  _MockKeyManagementService({this.publicKeyCompleter, this.gpgKeyCompleter});

  /// If set, listPublicKeys waits on this completer. Otherwise returns empty.
  final Completer<PublicKeyListResponse>? publicKeyCompleter;

  /// If set, listGpgKeys waits on this completer. Otherwise returns empty.
  final Completer<GpgKeyListResponse>? gpgKeyCompleter;

  @override
  Future<PublicKeyListResponse> listPublicKeys() {
    if (publicKeyCompleter != null) return publicKeyCompleter!.future;
    return Future.value(PublicKeyListResponse(keys: [], defaultKid: 'none'));
  }

  @override
  Future<GpgKeyListResponse> listGpgKeys() {
    if (gpgKeyCompleter != null) return gpgKeyCompleter!.future;
    return Future.value(GpgKeyListResponse(gpgKeys: []));
  }

  @override
  Future<void> addE2eKeyPair() async {}

  @override
  Future<void> deletePublicKey(String kid) async {}

  @override
  List<GpgParsedKey> parseGpgArmoredKey(String armoredKey) => [];

  @override
  Future<void> registerGpgKeys(List<GpgParsedKey> keys) async {}

  @override
  Future<void> deleteGpgKey(String keygrip) async {}

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
      // Never-completing future keeps the tab in loading state.
      final mock = _MockKeyManagementService(
        publicKeyCompleter: Completer<PublicKeyListResponse>(),
        gpgKeyCompleter: Completer<GpgKeyListResponse>(),
      );
      await tester.pumpWidget(_buildTestApp(mock));
      // One frame to trigger initState
      await tester.pump();

      // E2E tab is shown first — expect a loading indicator
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

      // Switch to GPG鍵 tab
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

      // Switch to GPG tab
      await tester.tap(find.text('GPG鍵'));
      await tester.pumpAndSettle();

      expect(find.text('登録されているGPG鍵はありません'), findsOneWidget);
    });
  });
}
