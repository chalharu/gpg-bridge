import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../security/gpg_key_models.dart';
import '../../state/key_management_service.dart';

/// GPG鍵インポートページ.
///
/// テキスト貼り付けによるアーマードキーの読み込みに対応しています。
/// ファイル読み込みは file_picker 導入後に追加する想定です。
class GpgKeyImportPage extends ConsumerStatefulWidget {
  const GpgKeyImportPage({super.key});

  @override
  ConsumerState<GpgKeyImportPage> createState() => _GpgKeyImportPageState();
}

class _GpgKeyImportPageState extends ConsumerState<GpgKeyImportPage> {
  final _textController = TextEditingController();
  List<GpgParsedKey>? _parsedKeys;
  Set<int> _selectedIndices = {};
  String? _parseError;
  bool _importing = false;

  @override
  void dispose() {
    _textController.dispose();
    super.dispose();
  }

  void _parse() {
    setState(() => _parseError = null);
    final text = _textController.text.trim();
    if (text.isEmpty) {
      setState(() => _parseError = 'アーマードキーを入力してください');
      return;
    }
    try {
      final keys = ref.read(keyManagementProvider).parseGpgArmoredKey(text);
      if (keys.isEmpty) {
        setState(() => _parseError = '有効な鍵が見つかりませんでした');
        return;
      }
      setState(() {
        _parsedKeys = keys;
        _selectedIndices = Set<int>.from(List.generate(keys.length, (i) => i));
      });
    } catch (e) {
      setState(() => _parseError = '解析に失敗しました: $e');
    }
  }

  Future<void> _import() async {
    final keys = _parsedKeys;
    if (keys == null || _selectedIndices.isEmpty) return;

    setState(() => _importing = true);
    try {
      final selected = _selectedIndices
          .map((i) => keys[i])
          .toList(growable: false);
      final service = ref.read(keyManagementProvider);

      // Store private key materials first, then register with server.
      // If server registration fails, clean up stored materials.
      for (final key in selected) {
        if (key.secretKeyMaterial != null) {
          await service.storeGpgPrivateKey(key.keygrip, key.secretKeyMaterial!);
        }
      }
      try {
        await service.registerGpgKeys(selected);
      } catch (_) {
        // Best-effort cleanup of stored private keys on API failure.
        for (final key in selected) {
          try {
            await service.deleteGpgPrivateKeyMaterial(key.keygrip);
          } catch (_) {}
        }
        rethrow;
      }

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('${selected.length}件の鍵をインポートしました')),
        );
        Navigator.pop(context);
      }
    } catch (e) {
      if (mounted) {
        setState(() => _importing = false);
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('インポートに失敗しました: $e')));
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final textTheme = Theme.of(context).textTheme;
    final colorScheme = Theme.of(context).colorScheme;

    return Scaffold(
      appBar: AppBar(title: const Text('GPG鍵インポート')),
      body: _importing
          ? const Center(child: CircularProgressIndicator())
          : SingleChildScrollView(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Text('アーマードキーを貼り付けてください', style: textTheme.bodyLarge),
                  const SizedBox(height: 8),
                  TextField(
                    controller: _textController,
                    maxLines: 10,
                    decoration: const InputDecoration(
                      border: OutlineInputBorder(),
                      hintText: '-----BEGIN PGP PUBLIC KEY BLOCK-----\n...',
                    ),
                  ),
                  const SizedBox(height: 12),
                  FilledButton.icon(
                    onPressed: _parse,
                    icon: const Icon(Icons.search),
                    label: const Text('解析'),
                  ),
                  if (_parseError != null) ...[
                    const SizedBox(height: 8),
                    Text(
                      _parseError!,
                      style: textTheme.bodyMedium?.copyWith(
                        color: colorScheme.error,
                      ),
                    ),
                  ],
                  if (_parsedKeys != null) ...[
                    const SizedBox(height: 16),
                    Text('検出された鍵', style: textTheme.titleMedium),
                    const SizedBox(height: 8),
                    ..._buildKeyList(),
                    const SizedBox(height: 16),
                    FilledButton.icon(
                      onPressed: _selectedIndices.isEmpty ? null : _import,
                      icon: const Icon(Icons.file_download),
                      label: Text('インポート (${_selectedIndices.length}件)'),
                    ),
                  ],
                ],
              ),
            ),
    );
  }

  List<Widget> _buildKeyList() {
    final keys = _parsedKeys!;
    final textTheme = Theme.of(context).textTheme;

    return List.generate(keys.length, (index) {
      final key = keys[index];
      final selected = _selectedIndices.contains(index);
      final hasSecret = key.secretKeyMaterial != null;

      return Card(
        child: CheckboxListTile(
          value: selected,
          onChanged: (value) {
            setState(() {
              if (value == true) {
                _selectedIndices.add(index);
              } else {
                _selectedIndices.remove(index);
              }
            });
          },
          title: Text(_keyTitle(key), style: textTheme.titleSmall),
          subtitle: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text('Key ID: ${key.keyId}'),
              Text('Keygrip: ${key.keygrip}'),
              if (hasSecret)
                Text(
                  '秘密鍵あり',
                  style: textTheme.bodySmall?.copyWith(
                    color: Theme.of(context).colorScheme.tertiary,
                  ),
                ),
            ],
          ),
          controlAffinity: ListTileControlAffinity.leading,
        ),
      );
    });
  }

  String _keyTitle(GpgParsedKey key) {
    final keyTypeLabel = key.isSubkey ? '(サブキー)' : '(主キー)';
    return '${key.algorithm.name}  $keyTypeLabel';
  }
}
