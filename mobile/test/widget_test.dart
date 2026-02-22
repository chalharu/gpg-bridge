import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'package:gpg_bridge_mobile/main.dart';

void main() {
  testWidgets('Registration flow routes to home', (WidgetTester tester) async {
    await tester.pumpWidget(const ProviderScope(child: GpgBridgeApp()));
    await tester.pumpAndSettle();

    expect(find.text('Register'), findsOneWidget);
    expect(find.text('Complete registration'), findsOneWidget);

    await tester.tap(find.text('Complete registration'));
    await tester.pumpAndSettle();

    expect(find.text('Home'), findsOneWidget);
    expect(find.text('Reset registration'), findsOneWidget);
  });
}
