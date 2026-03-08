import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gpg_bridge_mobile/pages/keys/key_tab_async_state.dart';

void main() {
  group('AsyncKeyTabState', () {
    testWidgets('ignores late load completion after dispose', (
      WidgetTester tester,
    ) async {
      final completer = Completer<String>();
      _AsyncKeyTabHarnessState? state;
      var visible = true;
      StateSetter? hostSetState;

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: StatefulBuilder(
              builder: (context, setState) {
                hostSetState = setState;
                return visible
                    ? _AsyncKeyTabHarness(
                        onStateReady: (value) => state = value,
                      )
                    : const SizedBox.shrink();
              },
            ),
          ),
        ),
      );
      await tester.pump();

      final future = state!.startLoad(completer.future);
      visible = false;
      hostSetState!.call(() {});
      await tester.pump();

      completer.complete('loaded');
      await future;

      expect(find.byType(_AsyncKeyTabHarness), findsNothing);
      expect(tester.takeException(), isNull);
    });

    testWidgets('ignores late load failure after dispose', (
      WidgetTester tester,
    ) async {
      final completer = Completer<String>();
      _AsyncKeyTabHarnessState? state;
      var visible = true;
      StateSetter? hostSetState;

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: StatefulBuilder(
              builder: (context, setState) {
                hostSetState = setState;
                return visible
                    ? _AsyncKeyTabHarness(
                        onStateReady: (value) => state = value,
                      )
                    : const SizedBox.shrink();
              },
            ),
          ),
        ),
      );
      await tester.pump();

      final future = state!.startLoad(completer.future);
      visible = false;
      hostSetState!.call(() {});
      await tester.pump();

      completer.completeError(Exception('late failure'));
      await future;

      expect(find.byType(_AsyncKeyTabHarness), findsNothing);
      expect(tester.takeException(), isNull);
    });

    testWidgets(
      'skips snackbar and reload when action completes after dispose',
      (WidgetTester tester) async {
        final completer = Completer<void>();
        _AsyncKeyTabHarnessState? state;
        var visible = true;
        StateSetter? hostSetState;

        await tester.pumpWidget(
          ProviderScope(
            child: MaterialApp(
              home: StatefulBuilder(
                builder: (context, setState) {
                  hostSetState = setState;
                  return visible
                      ? _AsyncKeyTabHarness(
                          onStateReady: (value) => state = value,
                        )
                      : const SizedBox.shrink();
                },
              ),
            ),
          ),
        );
        await tester.pump();

        final future = state!.startAction(completer.future, showLoading: true);
        expect(state!.isLoading, isTrue);

        visible = false;
        hostSetState!.call(() {});
        await tester.pump();

        completer.complete();
        await future;
        await tester.pumpAndSettle();

        expect(state!.reloadCount, 0);
        expect(find.byType(SnackBar), findsNothing);
      },
    );
  });
}

class _AsyncKeyTabHarness extends ConsumerStatefulWidget {
  const _AsyncKeyTabHarness({required this.onStateReady});

  final ValueChanged<_AsyncKeyTabHarnessState> onStateReady;

  @override
  ConsumerState<_AsyncKeyTabHarness> createState() =>
      _AsyncKeyTabHarnessState();
}

class _AsyncKeyTabHarnessState extends ConsumerState<_AsyncKeyTabHarness>
    with AsyncKeyTabState<String, _AsyncKeyTabHarness> {
  int reloadCount = 0;

  @override
  void initState() {
    super.initState();
    widget.onStateReady(this);
  }

  Future<void> startLoad(Future<String> future) {
    return loadData(() => future);
  }

  Future<void> startAction(Future<void> future, {bool showLoading = false}) {
    return runActionAndReload(
      action: () => future,
      reload: () async {
        reloadCount += 1;
      },
      successMessage: 'completed',
      errorMessageBuilder: (error) => 'failed: $error',
      showLoading: showLoading,
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: buildAsyncKeyTabBody(
        context: context,
        isLoading: isLoading,
        errorMessage: errorMessage,
        onRetry: () {},
        child: const Text('ready'),
      ),
    );
  }
}
