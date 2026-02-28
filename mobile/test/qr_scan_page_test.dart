import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:gpg_bridge_mobile/pages/qr_scan_page.dart';

void main() {
  group('QrScanPage', () {
    // MobileScanner uses native platform APIs that are not available in
    // unit tests. We verify the page widget can be constructed and has the
    // expected AppBar title. The scanner widget itself will fail to
    // initialize in test, so we catch that gracefully.

    testWidgets('renders AppBar with title', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(child: MaterialApp(home: QrScanPage())),
      );
      // Allow initial frame; scanner may throw platform error.
      await tester.pump();

      expect(find.text('QRコードスキャン'), findsOneWidget);
    });
  });

  group('jwtFormatPattern', () {
    test('matches valid JWT strings', () {
      expect(
        jwtFormatPattern.hasMatch(
          'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature',
        ),
        isTrue,
      );
      expect(jwtFormatPattern.hasMatch('abc.def.ghi'), isTrue);
      expect(jwtFormatPattern.hasMatch('a-b_c.d-e_f.g-h_i'), isTrue);
      expect(jwtFormatPattern.hasMatch('ABC123.DEF456.GHI789'), isTrue);
    });

    test('rejects invalid strings', () {
      expect(jwtFormatPattern.hasMatch(''), isFalse);
      expect(jwtFormatPattern.hasMatch('not-a-jwt'), isFalse);
      expect(jwtFormatPattern.hasMatch('only.two'), isFalse);
      expect(jwtFormatPattern.hasMatch('one.two.three.four'), isFalse);
      expect(jwtFormatPattern.hasMatch('has spaces.in.parts'), isFalse);
      expect(jwtFormatPattern.hasMatch('.empty.start'), isFalse);
      expect(jwtFormatPattern.hasMatch('empty..middle'), isFalse);
      expect(jwtFormatPattern.hasMatch('empty.end.'), isFalse);
      expect(jwtFormatPattern.hasMatch('https://example.com'), isFalse);
    });
  });
}
