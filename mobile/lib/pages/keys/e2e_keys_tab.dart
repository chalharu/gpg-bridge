import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../http/public_key_api_service.dart';
import '../../state/key_management_service.dart';
import 'delete_confirmation_dialog.dart';
import 'key_tab_async_state.dart';

class E2eKeysTab extends ConsumerStatefulWidget {
  const E2eKeysTab({super.key});

  @override
  ConsumerState<E2eKeysTab> createState() => _E2eKeysTabState();
}

class _E2eKeysTabState extends ConsumerState<E2eKeysTab>
    with AsyncKeyTabState<PublicKeyListResponse, E2eKeysTab> {
  @override
  void initState() {
    super.initState();
    _loadKeys();
  }

  Future<void> _loadKeys() =>
      loadData(() => ref.read(keyManagementProvider).listPublicKeys());

  Future<void> _addKeyPair() async {
    await runActionAndReload(
      action: () => ref.read(keyManagementProvider).addE2eKeyPair(),
      reload: _loadKeys,
      successMessage: '鍵ペアを生成しました',
      errorMessageBuilder: (error) => '鍵ペアの生成に失敗しました: $error',
      showLoading: true,
    );
  }

  Future<void> _deleteKey(String kid) async {
    final confirmed = await showDeleteConfirmationDialog(
      context,
      title: '鍵の削除',
      content: 'この公開鍵を削除しますか？\nkid: $kid',
    );
    if (!confirmed) {
      return;
    }

    await runActionAndReload(
      action: () => ref.read(keyManagementProvider).deletePublicKey(kid),
      reload: _loadKeys,
      successMessage: '鍵を削除しました',
      errorMessageBuilder: (error) => '削除に失敗しました: $error',
    );
  }

  String _useLabel(String? use) {
    switch (use) {
      case 'sig':
        return '認証用';
      case 'enc':
        return '暗号化用';
      default:
        return use ?? '不明';
    }
  }

  String _truncateKid(String kid) {
    if (kid.length <= 12) return kid;
    return '${kid.substring(0, 8)}…';
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;

    final keys = data?.keys ?? [];
    final defaultKid = data?.defaultKid;

    return Scaffold(
      body: buildAsyncKeyTabBody(
        context: context,
        isLoading: isLoading,
        errorMessage: errorMessage,
        onRetry: _loadKeys,
        child: keys.isEmpty
            ? const Center(child: Text('登録されている公開鍵はありません'))
            : RefreshIndicator(
                onRefresh: _loadKeys,
                child: ListView.builder(
                  padding: const EdgeInsets.all(8),
                  itemCount: keys.length,
                  itemBuilder: (context, index) {
                    final jwk = keys[index];
                    final kid = jwk['kid'] as String? ?? '';
                    final use = jwk['use'] as String?;
                    final alg =
                        jwk['alg'] as String? ?? jwk['kty'] as String? ?? '';
                    final isDefault = kid == defaultKid;

                    return Card(
                      child: ListTile(
                        leading: isDefault
                            ? Icon(Icons.star, color: colorScheme.primary)
                            : const Icon(Icons.key),
                        title: Text(
                          '${_useLabel(use)}  $alg',
                          style: textTheme.titleSmall,
                        ),
                        subtitle: Text('kid: ${_truncateKid(kid)}'),
                        trailing: IconButton(
                          icon: Icon(Icons.delete, color: colorScheme.error),
                          onPressed: () => _deleteKey(kid),
                        ),
                      ),
                    );
                  },
                ),
              ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: _addKeyPair,
        tooltip: '鍵ペアを生成',
        child: const Icon(Icons.add),
      ),
    );
  }
}
