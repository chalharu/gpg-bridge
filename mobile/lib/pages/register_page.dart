import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../http/api_config.dart';
import '../http/device_api_service.dart';
import '../http/server_url_service.dart';
import '../state/device_registration_service.dart';

class RegisterPage extends ConsumerStatefulWidget {
  const RegisterPage({super.key});

  @override
  ConsumerState<RegisterPage> createState() => _RegisterPageState();
}

class _RegisterPageState extends ConsumerState<RegisterPage> {
  late final TextEditingController _serverUrlController;
  bool _isLoading = false;
  String? _serverUrlError;
  String? _validationMessage;

  @override
  void initState() {
    super.initState();
    _serverUrlController = TextEditingController();
    _loadInitialServerUrl();
  }

  @override
  void dispose() {
    _serverUrlController.dispose();
    super.dispose();
  }

  Future<void> _loadInitialServerUrl() async {
    final serverUrlService = ref.read(serverUrlServiceProvider);
    try {
      final initialValue = await serverUrlService.getSavedOrDefault();
      if (!mounted) return;
      _serverUrlController.text = initialValue;
      setState(() {
        _serverUrlError = null;
        _validationMessage = null;
      });
    } on ServerUrlException catch (error) {
      if (!mounted) return;
      _serverUrlController.text = ApiConfig.baseUrl;
      setState(() {
        _serverUrlError = error.message;
        _validationMessage = null;
      });
    }
  }

  void _handleServerUrlChanged(String value) {
    final serverUrlService = ref.read(serverUrlServiceProvider);
    try {
      serverUrlService.normalize(value);
      setState(() {
        _serverUrlError = null;
        _validationMessage = null;
      });
    } on ServerUrlException catch (error) {
      setState(() {
        _serverUrlError = error.message;
        _validationMessage = null;
      });
    }
  }

  Future<void> _handleRegistration() async {
    final serverUrlService = ref.read(serverUrlServiceProvider);
    late final String serverUrl;

    try {
      serverUrl = serverUrlService.normalize(_serverUrlController.text);
    } on ServerUrlException catch (error) {
      setState(() {
        _serverUrlError = error.message;
        _validationMessage = null;
      });
      return;
    }

    setState(() => _isLoading = true);
    try {
      await ref
          .read(deviceApiProvider)
          .validateServerConnection(serverUrl: serverUrl);
      if (!mounted) return;
      setState(() {
        _serverUrlError = null;
        _validationMessage = 'Connected to $serverUrl';
      });

      final service = ref.read(deviceRegistrationProvider);
      await service.register(serverUrl: serverUrl);
      service.startTokenRefreshListener();
    } on DeviceRegistrationException catch (error) {
      if (!mounted) return;
      setState(() {
        _validationMessage = null;
      });
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(error.message)));
    } on DeviceApiException catch (error) {
      if (!mounted) return;
      setState(() {
        _validationMessage = 'Unable to reach $serverUrl';
      });
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(error.message)));
    } finally {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  bool get _canSubmit {
    return !_isLoading &&
        _serverUrlController.text.trim().isNotEmpty &&
        _serverUrlError == null;
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      appBar: AppBar(title: const Text('Register')),
      body: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Text(
              'Choose the server used for device registration.',
              style: theme.textTheme.bodyLarge,
            ),
            const SizedBox(height: 16),
            TextField(
              controller: _serverUrlController,
              keyboardType: TextInputType.url,
              autofillHints: const [AutofillHints.url],
              onChanged: _handleServerUrlChanged,
              decoration: InputDecoration(
                labelText: 'Server URL',
                hintText: 'https://api.example.com',
                errorText: _serverUrlError,
              ),
            ),
            const SizedBox(height: 12),
            if (_validationMessage != null)
              Text(_validationMessage!, style: theme.textTheme.bodyMedium),
            const SizedBox(height: 24),
            if (_isLoading)
              Column(
                children: [
                  const CircularProgressIndicator(),
                  const SizedBox(height: 12),
                  Text(
                    'Registering with ${_serverUrlController.text.trim()}',
                    textAlign: TextAlign.center,
                  ),
                ],
              )
            else
              ElevatedButton(
                onPressed: _canSubmit ? _handleRegistration : null,
                child: const Text('Complete registration'),
              ),
          ],
        ),
      ),
    );
  }
}
