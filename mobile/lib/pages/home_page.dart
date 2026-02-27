import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../state/device_registration_service.dart';

class HomePage extends ConsumerStatefulWidget {
  const HomePage({super.key});

  @override
  ConsumerState<HomePage> createState() => _HomePageState();
}

class _HomePageState extends ConsumerState<HomePage> {
  bool _isLoading = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final service = ref.read(deviceRegistrationProvider);
      service.startTokenRefreshListener();
      service.checkAndRefreshDeviceJwt();
      service.checkAndRefreshFcmToken();
    });
  }

  Future<void> _handleUnregister() async {
    setState(() => _isLoading = true);
    try {
      await ref.read(deviceRegistrationProvider).unregister();
    } on DeviceRegistrationException catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(error.message)));
    } finally {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('ホーム')),
      body: Center(
        child: _isLoading
            ? const CircularProgressIndicator()
            : ElevatedButton(
                onPressed: _handleUnregister,
                child: const Text('Reset registration'),
              ),
      ),
    );
  }
}
