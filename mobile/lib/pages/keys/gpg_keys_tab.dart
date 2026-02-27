import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

// NOTE: Loading/error state pattern shared with E2eKeysTab.
// Consider extracting a mixin if more tabs are added.

import '../../http/gpg_key_api_service.dart';
import '../../state/key_management_service.dart';
import 'delete_confirmation_dialog.dart';
import 'gpg_key_import_page.dart';

class GpgKeysTab extends ConsumerStatefulWidget {
  const GpgKeysTab({super.key});

  @override
  ConsumerState<GpgKeysTab> createState() => _GpgKeysTabState();
}

class _GpgKeysTabState extends ConsumerState<GpgKeysTab> {
  GpgKeyListResponse? _data;
  String? _error;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _loadKeys();
  }

  Future<void> _loadKeys() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final result = await ref.read(keyManagementProvider).listGpgKeys();
      if (mounted) {
        setState(() {
          _data = result;
          _loading = false;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = e.toString();
          _loading = false;
        });
      }
    }
  }

  Future<void> _openImportPage() async {
    await Navigator.push<void>(
      context,
      MaterialPageRoute(builder: (_) => const GpgKeyImportPage()),
    );
    await _loadKeys();
  }

  Future<void> _deleteKey(GpgKeyEntry entry) async {
    final confirmed = await showDeleteConfirmationDialog(
      context,
      title: 'GPG鍵の削除',
      content: 'このGPG鍵を削除しますか？\nKeygrip: ${entry.keygrip}',
    );
    if (!confirmed) return;
    try {
      final service = ref.read(keyManagementProvider);
      await service.deleteGpgKey(entry.keygrip);
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(const SnackBar(content: Text('GPG鍵を削除しました')));
      }
      await _loadKeys();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('削除に失敗しました: $e')));
      }
    }
  }

  String _truncate(String value, {int maxLength = 16}) {
    if (value.length <= maxLength) return value;
    return '${value.substring(0, maxLength)}…';
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;

    if (_loading) {
      return const Center(child: CircularProgressIndicator());
    }

    if (_error != null) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text('読み込みに失敗しました', style: textTheme.bodyLarge),
            const SizedBox(height: 8),
            Text(_error!, style: textTheme.bodySmall),
            const SizedBox(height: 16),
            ElevatedButton(onPressed: _loadKeys, child: const Text('再試行')),
          ],
        ),
      );
    }

    final keys = _data?.gpgKeys ?? [];

    return Scaffold(
      body: keys.isEmpty
          ? const Center(child: Text('登録されているGPG鍵はありません'))
          : RefreshIndicator(
              onRefresh: _loadKeys,
              child: ListView.builder(
                padding: const EdgeInsets.all(8),
                itemCount: keys.length,
                itemBuilder: (context, index) {
                  final entry = keys[index];
                  return Card(
                    child: ListTile(
                      leading: const Icon(Icons.vpn_key),
                      title: Text(
                        'Key ID: ${entry.keyId}',
                        style: textTheme.titleSmall,
                      ),
                      subtitle: Text('Keygrip: ${_truncate(entry.keygrip)}'),
                      trailing: IconButton(
                        icon: Icon(Icons.delete, color: colorScheme.error),
                        onPressed: () => _deleteKey(entry),
                      ),
                    ),
                  );
                },
              ),
            ),
      floatingActionButton: FloatingActionButton(
        onPressed: _openImportPage,
        tooltip: 'GPG鍵をインポート',
        child: const Icon(Icons.file_upload),
      ),
    );
  }
}
