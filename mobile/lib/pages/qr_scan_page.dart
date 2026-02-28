import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../state/pairing_state.dart';
import '../state/pairing_types.dart';

/// JWT format pattern matching OpenAPI spec: three Base64url segments separated by dots.
final jwtFormatPattern = RegExp(
  r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$',
);

class QrScanPage extends ConsumerStatefulWidget {
  const QrScanPage({super.key});

  @override
  ConsumerState<QrScanPage> createState() => _QrScanPageState();
}

class _QrScanPageState extends ConsumerState<QrScanPage> {
  bool _isProcessing = false;

  Future<void> _handleDetection(BarcodeCapture capture) async {
    if (_isProcessing) return;
    final barcode = capture.barcodes.firstOrNull;
    if (barcode == null) return;
    final rawValue = barcode.rawValue;
    if (rawValue == null || rawValue.isEmpty) return;

    if (!jwtFormatPattern.hasMatch(rawValue)) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('有効なペアリングQRコードではありません')));
      return;
    }

    setState(() => _isProcessing = true);
    try {
      await ref.read(pairingStateProvider.notifier).pair(rawValue);
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('ペアリングに成功しました')));
      Navigator.of(context).pop();
    } on PairingException catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(error.message)));
      setState(() => _isProcessing = false);
    } catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text('ペアリングに失敗しました: $error')));
      setState(() => _isProcessing = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('QRコードスキャン')),
      body: _isProcessing
          ? const Center(child: CircularProgressIndicator())
          : MobileScanner(onDetect: _handleDetection),
    );
  }
}
