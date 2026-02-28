import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../state/pairing_state.dart';
import '../state/pairing_types.dart';

class PairingPage extends ConsumerWidget {
  const PairingPage({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final pairingsAsync = ref.watch(pairingStateProvider);

    return Scaffold(
      appBar: AppBar(title: const Text('ペアリング')),
      body: pairingsAsync.when(
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (error, _) => Center(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Text('ペアリング情報の読み込みに失敗しました'),
              const SizedBox(height: 16),
              ElevatedButton(
                onPressed: () => ref.invalidate(pairingStateProvider),
                child: const Text('再試行'),
              ),
            ],
          ),
        ),
        data: (pairings) => _PairingList(pairings: pairings),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: () => context.push('/pairing/scan'),
        child: const Icon(Icons.qr_code_scanner),
      ),
    );
  }
}

class _PairingList extends ConsumerWidget {
  const _PairingList({required this.pairings});

  final List<PairingRecord> pairings;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    if (pairings.isEmpty) {
      return const Center(child: Text('ペアリングされたデバイスはありません'));
    }
    return ListView.builder(
      itemCount: pairings.length,
      itemBuilder: (context, index) {
        final record = pairings[index];
        return _PairingTile(record: record);
      },
    );
  }
}

class _PairingTile extends ConsumerStatefulWidget {
  const _PairingTile({required this.record});

  final PairingRecord record;

  @override
  ConsumerState<_PairingTile> createState() => _PairingTileState();
}

class _PairingTileState extends ConsumerState<_PairingTile> {
  bool _isDeleting = false;

  Future<void> _confirmUnpair() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('ペアリング解除'),
        content: const Text('このデバイスとのペアリングを解除しますか？'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('キャンセル'),
          ),
          TextButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('解除'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;
    await _performUnpair();
  }

  Future<void> _performUnpair() async {
    setState(() => _isDeleting = true);
    try {
      await ref
          .read(pairingStateProvider.notifier)
          .unpair(widget.record.pairingId);
    } on PairingException catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(error.message)));
    } catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text('解除に失敗しました: $error')));
    } finally {
      if (mounted) setState(() => _isDeleting = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final record = widget.record;
    return ListTile(
      title: Text(record.clientId),
      subtitle: Text(
        'ID: ${record.pairingId}\n'
        'ペアリング日時: ${_formatDate(record.pairedAt)}',
      ),
      isThreeLine: true,
      trailing: _isDeleting
          ? const SizedBox(
              width: 24,
              height: 24,
              child: CircularProgressIndicator(strokeWidth: 2),
            )
          : IconButton(
              icon: const Icon(Icons.delete_outline),
              onPressed: _confirmUnpair,
            ),
    );
  }

  String _formatDate(DateTime date) {
    return '${date.year}/${date.month.toString().padLeft(2, '0')}/'
        '${date.day.toString().padLeft(2, '0')} '
        '${date.hour.toString().padLeft(2, '0')}:'
        '${date.minute.toString().padLeft(2, '0')}';
  }
}
