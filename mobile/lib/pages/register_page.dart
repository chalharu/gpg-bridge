import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../security/secure_storage_service.dart';
import '../state/auth_state.dart';

class RegisterPage extends ConsumerWidget {
  const RegisterPage({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return Scaffold(
      appBar: AppBar(title: const Text('Register')),
      body: Center(
        child: ElevatedButton(
          onPressed: () async {
            try {
              await ref
                  .read(secureStorageProvider)
                  .writeValue(
                    key: SecureStorageKeys.deviceToken,
                    value: 'registered-device-token',
                  );
              ref.read(authStateProvider.notifier).setRegistered(true);
            } on SecureStorageException catch (error) {
              if (!context.mounted) {
                return;
              }
              ScaffoldMessenger.of(
                context,
              ).showSnackBar(SnackBar(content: Text(error.message)));
            }
          },
          child: const Text('Complete registration'),
        ),
      ),
    );
  }
}
