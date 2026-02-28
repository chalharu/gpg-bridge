import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'fcm/fcm_message_handler.dart';
import 'router/app_router.dart';
import 'state/sign_request_state.dart';
import 'state/theme_mode_state.dart';
import 'theme/app_theme.dart';

void main() {
  runApp(const ProviderScope(child: GpgBridgeApp()));
}

class GpgBridgeApp extends ConsumerStatefulWidget {
  const GpgBridgeApp({super.key});

  @override
  ConsumerState<GpgBridgeApp> createState() => _GpgBridgeAppState();
}

class _GpgBridgeAppState extends ConsumerState<GpgBridgeApp> {
  @override
  void initState() {
    super.initState();
    _initFcmListeners();
  }

  void _initFcmListeners() {
    FirebaseMessaging.onMessage.listen(_handleFcmMessage);
    FirebaseMessaging.onMessageOpenedApp.listen(_handleFcmMessage);
  }

  void _handleFcmMessage(RemoteMessage message) {
    final parsed = parseFcmData(message.data);
    if (parsed == null) return;

    switch (parsed.type) {
      case FcmMessageType.signRequest:
        ref.read(signRequestStateProvider.notifier).refresh();
        final requestId = parsed.requestId;
        if (requestId != null) {
          _navigateToSignRequest(requestId);
        }
      case FcmMessageType.signRequestCancelled:
        final requestId = parsed.requestId;
        if (requestId != null) {
          ref.read(signRequestStateProvider.notifier).dismiss(requestId);
        }
    }
  }

  void _navigateToSignRequest(String requestId) {
    final router = ref.read(appRouterProvider);
    router.push('/sign-request/$requestId');
  }

  @override
  Widget build(BuildContext context) {
    final router = ref.watch(appRouterProvider);
    final themeMode = ref.watch(themeModeStateProvider);

    return MaterialApp.router(
      title: 'GPG Bridge',
      theme: AppTheme.light(),
      darkTheme: AppTheme.dark(),
      themeMode: themeMode,
      routerConfig: router,
    );
  }
}
