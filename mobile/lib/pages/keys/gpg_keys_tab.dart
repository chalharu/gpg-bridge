import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../http/gpg_key_api_service.dart';
import '../../state/key_management_service.dart';
import 'delete_confirmation_dialog.dart';
import 'gpg_key_import_page.dart';
import 'key_tab_async_state.dart';

class GpgKeysTab extends ConsumerStatefulWidget {
  const GpgKeysTab({super.key});

  @override
  ConsumerState<GpgKeysTab> createState() => _GpgKeysTabState();
}

class _GpgKeysTabState extends ConsumerState<GpgKeysTab>
    with AsyncKeyTabState<GpgKeyListResponse, GpgKeysTab> {
  @override
  void initState() {
    super.initState();
    _loadKeys();
  }

  Future<void> _loadKeys() =>
      loadData(() => ref.read(keyManagementProvider).listGpgKeys());

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
    if (!confirmed) {
      return;
    }

    final service = ref.read(keyManagementProvider);
    await runActionAndReload(
      action: () => service.deleteGpgKey(entry.keygrip),
      reload: _loadKeys,
      successMessage: 'GPG鍵を削除しました',
      errorMessageBuilder: (error) => '削除に失敗しました: $error',
    );
  }

  String _truncate(String value, {int maxLength = 16}) {
    if (value.length <= maxLength) return value;
    return '${value.substring(0, maxLength)}…';
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;

    final keys = data?.gpgKeys ?? [];

    return Scaffold(
      body: buildAsyncKeyTabBody(
        context: context,
        isLoading: isLoading,
        errorMessage: errorMessage,
        onRetry: _loadKeys,
        child: keys.isEmpty
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
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: _openImportPage,
        tooltip: 'GPG鍵をインポート',
        child: const Icon(Icons.file_upload),
      ),
    );
  }
}
