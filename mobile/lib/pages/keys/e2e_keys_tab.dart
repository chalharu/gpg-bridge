import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

// NOTE: Loading/error state pattern shared with GpgKeysTab.
// Consider extracting a mixin if more tabs are added.

import '../../http/public_key_api_service.dart';
import '../../state/key_management_service.dart';
import 'delete_confirmation_dialog.dart';

class E2eKeysTab extends ConsumerStatefulWidget {
  const E2eKeysTab({super.key});

  @override
  ConsumerState<E2eKeysTab> createState() => _E2eKeysTabState();
}

class _E2eKeysTabState extends ConsumerState<E2eKeysTab> {
  PublicKeyListResponse? _data;
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
      final result = await ref.read(keyManagementProvider).listPublicKeys();
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

  Future<void> _addKeyPair() async {
    setState(() => _loading = true);
    try {
      await ref.read(keyManagementProvider).addE2eKeyPair();
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(const SnackBar(content: Text('鍵ペアを生成しました')));
      }
      await _loadKeys();
    } catch (e) {
      if (mounted) {
        setState(() => _loading = false);
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('鍵ペアの生成に失敗しました: $e')));
      }
    }
  }

  Future<void> _deleteKey(String kid) async {
    final confirmed = await showDeleteConfirmationDialog(
      context,
      title: '鍵の削除',
      content: 'この公開鍵を削除しますか？\nkid: $kid',
    );
    if (!confirmed) return;
    try {
      await ref.read(keyManagementProvider).deletePublicKey(kid);
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(const SnackBar(content: Text('鍵を削除しました')));
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

    final keys = _data?.keys ?? [];
    final defaultKid = _data?.defaultKid;

    return Scaffold(
      body: keys.isEmpty
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
      floatingActionButton: FloatingActionButton(
        onPressed: _addKeyPair,
        tooltip: '鍵ペアを生成',
        child: const Icon(Icons.add),
      ),
    );
  }
}
