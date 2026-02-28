import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/state/pairing_state.dart';
import 'package:gpg_bridge_mobile/state/pairing_types.dart';

import 'package:gpg_bridge_mobile/pages/pairing_page.dart';

void main() {
  group('PairingPage', () {
    testWidgets('shows loading indicator while loading', (tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            pairingStateProvider.overrideWith(() => _LoadingPairingState()),
          ],
          child: const MaterialApp(home: PairingPage()),
        ),
      );

      expect(find.byType(CircularProgressIndicator), findsOneWidget);
    });

    testWidgets('shows empty message when no pairings', (tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            pairingStateProvider.overrideWith(() => _EmptyPairingState()),
          ],
          child: const MaterialApp(home: PairingPage()),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.text('ペアリングされたデバイスはありません'), findsOneWidget);
    });

    testWidgets('shows pairing records', (tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            pairingStateProvider.overrideWith(() => _PopulatedPairingState()),
          ],
          child: const MaterialApp(home: PairingPage()),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.text('test-client'), findsOneWidget);
      expect(find.text('ペアリング'), findsOneWidget); // AppBar title
    });

    testWidgets('shows error state with retry button', (tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            pairingStateProvider.overrideWith(() => _ErrorPairingState()),
          ],
          child: const MaterialApp(home: PairingPage()),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.text('ペアリング情報の読み込みに失敗しました'), findsOneWidget);
      expect(find.text('再試行'), findsOneWidget);
      expect(find.byType(ElevatedButton), findsOneWidget);
    });

    testWidgets('has FAB with QR scanner icon', (tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            pairingStateProvider.overrideWith(() => _EmptyPairingState()),
          ],
          child: const MaterialApp(home: PairingPage()),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.byType(FloatingActionButton), findsOneWidget);
      expect(find.byIcon(Icons.qr_code_scanner), findsOneWidget);
    });

    testWidgets('shows confirmation dialog on delete tap', (tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            pairingStateProvider.overrideWith(() => _PopulatedPairingState()),
          ],
          child: const MaterialApp(home: PairingPage()),
        ),
      );
      await tester.pumpAndSettle();

      await tester.tap(find.byIcon(Icons.delete_outline));
      await tester.pumpAndSettle();

      expect(find.text('ペアリング解除'), findsOneWidget);
      expect(find.text('キャンセル'), findsOneWidget);
      expect(find.text('解除'), findsOneWidget);
    });
  });
}

class _LoadingPairingState extends PairingState {
  @override
  Future<List<PairingRecord>> build() async {
    // Never completes to keep in loading state.
    return Future<List<PairingRecord>>.delayed(const Duration(days: 1));
  }
}

class _EmptyPairingState extends PairingState {
  @override
  Future<List<PairingRecord>> build() async => [];
}

class _PopulatedPairingState extends PairingState {
  @override
  Future<List<PairingRecord>> build() async => [
    PairingRecord(
      pairingId: 'p-test-1',
      clientId: 'test-client',
      pairedAt: DateTime.utc(2025, 6, 15, 10, 30),
    ),
  ];
}

class _ErrorPairingState extends PairingState {
  @override
  Future<List<PairingRecord>> build() async {
    throw Exception('load failed');
  }
}
