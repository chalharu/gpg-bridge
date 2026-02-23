import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../state/theme_mode_state.dart';

class SettingsPage extends ConsumerWidget {
  const SettingsPage({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final themeMode = ref.watch(themeModeStateProvider);

    return Scaffold(
      appBar: AppBar(title: const Text('設定')),
      body: ListView(
        children: [
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
            child: Column(
              children: [
                const RadioListTile<ThemeMode>(
                  title: Text('システム設定に従う'),
                  value: ThemeMode.system,
                ),
                const RadioListTile<ThemeMode>(
                  title: Text('ライト'),
                  value: ThemeMode.light,
                ),
                const RadioListTile<ThemeMode>(
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
