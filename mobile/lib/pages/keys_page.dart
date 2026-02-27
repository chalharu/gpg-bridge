import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'keys/e2e_keys_tab.dart';
import 'keys/gpg_keys_tab.dart';

class KeysPage extends ConsumerWidget {
  const KeysPage({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return DefaultTabController(
      length: 2,
      child: Scaffold(
        appBar: AppBar(
          title: const Text('鍵管理'),
          bottom: const TabBar(
            tabs: [
              Tab(text: 'E2E公開鍵'),
              Tab(text: 'GPG鍵'),
            ],
          ),
        ),
        body: const TabBarView(children: [E2eKeysTab(), GpgKeysTab()]),
      ),
    );
  }
}
