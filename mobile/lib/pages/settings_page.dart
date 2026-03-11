import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../http/server_url_service.dart';
import '../state/theme_mode_state.dart';

final settingsServerUrlProvider = FutureProvider<String>((ref) async {
  return ref.read(serverUrlServiceProvider).getSavedOrDefault();
});

class SettingsPage extends ConsumerWidget {
  const SettingsPage({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final themeMode = ref.watch(themeModeStateProvider);
    final serverUrlAsync = ref.watch(settingsServerUrlProvider);

    return Scaffold(
      appBar: AppBar(title: const Text('設定')),
      body: ListView(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
            child: Card(
              child: ListTile(
                title: const Text('接続サーバー'),
                subtitle: serverUrlAsync.when(
                  data: (serverUrl) => Text(serverUrl),
                  loading: () => const Text('読み込み中...'),
                  error: (_, _) => const Text('接続サーバーを取得できませんでした'),
                ),
              ),
            ),
          ),
          Padding(
            padding: const EdgeInsets.all(16),
            child: Text('テーマ', style: Theme.of(context).textTheme.titleMedium),
          ),
          RadioGroup<ThemeMode>(
            groupValue: themeMode,
            onChanged: (value) {
              if (value != null) {
                ref.read(themeModeStateProvider.notifier).setThemeMode(value);
              }
            },
            child: const Column(
              children: [
                RadioListTile<ThemeMode>(
                  title: Text('システム設定に従う'),
                  value: ThemeMode.system,
                ),
                RadioListTile<ThemeMode>(
                  title: Text('ライト'),
                  value: ThemeMode.light,
                ),
                RadioListTile<ThemeMode>(
                  title: Text('ダーク'),
                  value: ThemeMode.dark,
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
