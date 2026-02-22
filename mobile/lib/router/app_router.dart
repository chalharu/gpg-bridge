import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';

import '../security/secure_storage_service.dart';
import '../state/auth_state.dart';

part 'app_router.g.dart';

@riverpod
GoRouter appRouter(Ref ref) {
  return GoRouter(
    initialLocation: '/register',
    routes: [
      GoRoute(
        path: '/register',
        builder: (context, state) => const RegisterPage(),
      ),
      GoRoute(path: '/', builder: (context, state) => const HomePage()),
    ],
    redirect: (context, state) {
      final isRegistered = ref.read(authStateProvider);
      final inRegister = state.matchedLocation == '/register';

      if (!isRegistered && !inRegister) {
        return '/register';
      }

      if (isRegistered && inRegister) {
        return '/';
      }

      return null;
    },
    refreshListenable: _RouterRefreshListenable(ref),
  );
}

class _RouterRefreshListenable extends ChangeNotifier {
  _RouterRefreshListenable(this.ref) {
    _subscription = ref.listen<bool>(
      authStateProvider,
      (_, next) => notifyListeners(),
    );
  }

  final Ref ref;
  late final ProviderSubscription<bool> _subscription;

  @override
  void dispose() {
    _subscription.close();
    super.dispose();
  }
}

class RegisterPage extends ConsumerWidget {
  const RegisterPage({super.key});

  static const _deviceTokenKey = 'device_token';

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
                    key: _deviceTokenKey,
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

class HomePage extends ConsumerWidget {
  const HomePage({super.key});

  static const _deviceTokenKey = 'device_token';

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return Scaffold(
      appBar: AppBar(title: const Text('Home')),
      body: Center(
        child: ElevatedButton(
          onPressed: () async {
            try {
              await ref
                  .read(secureStorageProvider)
                  .deleteValue(key: _deviceTokenKey);
              ref.read(authStateProvider.notifier).setRegistered(false);
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
