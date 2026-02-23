import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';

import '../pages/home_page.dart';
import '../pages/keys_page.dart';
import '../pages/main_shell.dart';
import '../pages/pairing_page.dart';
import '../pages/register_page.dart';
import '../pages/settings_page.dart';
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
      StatefulShellRoute.indexedStack(
        builder: (context, state, navigationShell) {
          return MainShell(navigationShell: navigationShell);
        },
        branches: [
          StatefulShellBranch(
            routes: [
              GoRoute(path: '/', builder: (context, state) => const HomePage()),
            ],
          ),
          StatefulShellBranch(
            routes: [
              GoRoute(
                path: '/keys',
                builder: (context, state) => const KeysPage(),
              ),
            ],
          ),
          StatefulShellBranch(
            routes: [
              GoRoute(
                path: '/pairing',
                builder: (context, state) => const PairingPage(),
              ),
            ],
          ),
          StatefulShellBranch(
            routes: [
              GoRoute(
                path: '/settings',
                builder: (context, state) => const SettingsPage(),
              ),
            ],
          ),
        ],
      ),
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
