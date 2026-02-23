import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../security/secure_storage_service.dart';
import '../state/auth_state.dart';

class HomePage extends ConsumerWidget {
  const HomePage({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return Scaffold(
      appBar: AppBar(title: const Text('ホーム')),
      body: Center(
        child: ElevatedButton(
          onPressed: () async {
            try {
              await ref
                  .read(secureStorageProvider)
                  .deleteValue(key: SecureStorageKeys.deviceToken);
              await ref.read(authStateProvider.notifier).setRegistered(false);
            } on SecureStorageException catch (error) {
              if (!context.mounted) {
                return;
              }
              ScaffoldMessenger.of(
                context,
              ).showSnackBar(SnackBar(content: Text(error.message)));
            }
          },
          child: const Text('Reset registration'),
        ),
      ),
    );
  }
}
