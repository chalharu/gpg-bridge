import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../state/sign_request_state.dart';
import 'widgets/action_buttons.dart';
import 'widgets/countdown_banner.dart';
import 'widgets/detail_card.dart';

/// Page displayed when a sign request is received via FCM push.
///
/// Shows the hash, algorithm, and key ID for user review, with
/// approve / deny / ignore actions and a countdown until expiry.
class SignRequestPage extends ConsumerStatefulWidget {
  const SignRequestPage({super.key, required this.requestId});

  /// Route path template for go_router configuration.
  static const routePath = '/sign-request/:requestId';

  final String requestId;

  @override
  ConsumerState<SignRequestPage> createState() => _SignRequestPageState();
}

class _SignRequestPageState extends ConsumerState<SignRequestPage> {
  Timer? _timer;
  Duration _remaining = const Duration(minutes: 5);
  bool _isSubmitting = false;

  @override
  void initState() {
    super.initState();
    _initCountdown();
  }

  void _initCountdown() {
    // Calculate initial countdown from request expiry (#5).
    final request = _findRequest();
    if (request != null) {
      final remaining = request.expiresAt.difference(DateTime.now());
      _remaining = remaining.isNegative ? Duration.zero : remaining;
    }
    _startCountdown();
  }

  void _startCountdown() {
    _timer = Timer.periodic(const Duration(seconds: 1), (_) {
      // Guard against post-dispose ref access (#11).
      if (!mounted) return;
      final request = _findRequest();
      if (request == null) {
        _timer?.cancel();
        return;
      }
      final remaining = request.expiresAt.difference(DateTime.now());
      setState(() {
        _remaining = remaining.isNegative ? Duration.zero : remaining;
      });
      if (remaining.isNegative) {
        _timer?.cancel();
        _handleExpired();
      }
    });
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  DecryptedSignRequest? _findRequest() {
    final requests = ref.read(signRequestStateProvider).value;
    if (requests == null) return null;
    try {
      return requests.firstWhere((r) => r.requestId == widget.requestId);
    } on StateError {
      return null;
    }
  }

  Future<void> _handleApprove(DecryptedSignRequest request) async {
    setState(() => _isSubmitting = true);
    try {
      await ref.read(signRequestStateProvider.notifier).approve(request);
      if (mounted) Navigator.of(context).pop();
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text('署名に失敗しました: $e')));
    } finally {
      if (mounted) setState(() => _isSubmitting = false);
    }
  }

  Future<void> _handleDeny(DecryptedSignRequest request) async {
    setState(() => _isSubmitting = true);
    try {
      await ref.read(signRequestStateProvider.notifier).deny(request);
      if (mounted) Navigator.of(context).pop();
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text('拒否に失敗しました: $e')));
    } finally {
      if (mounted) setState(() => _isSubmitting = false);
    }
  }

  void _handleIgnore() {
    Navigator.of(context).pop();
  }

  void _handleExpired() {
    if (!mounted) return;
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(const SnackBar(content: Text('署名要求がタイムアウトしました')));
    Navigator.of(context).pop();
  }

  @override
  Widget build(BuildContext context) {
    final asyncRequests = ref.watch(signRequestStateProvider);

    // Handle loading / error states (#6).
    return Scaffold(
      appBar: AppBar(title: const Text('署名要求')),
      body: asyncRequests.when(
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (error, _) => Center(child: Text('エラー: $error')),
        data: (requests) {
          final request = requests.cast<DecryptedSignRequest?>().firstWhere(
            (r) => r?.requestId == widget.requestId,
            orElse: () => null,
          );
          if (request == null) {
            return const Center(child: Text('署名要求が見つかりません'));
          }
          return _buildBody(request);
        },
      ),
    );
  }

  Widget _buildBody(DecryptedSignRequest request) {
    final minutes = _remaining.inMinutes;
    final seconds = _remaining.inSeconds % 60;
    final timerText =
        '${minutes.toString().padLeft(2, '0')}:'
        '${seconds.toString().padLeft(2, '0')}';

    return Padding(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          CountdownBanner(timerText: timerText, remaining: _remaining),
          const SizedBox(height: 24),
          DetailCard(request: request),
          const Spacer(),
          ActionButtons(
            isSubmitting: _isSubmitting,
            onApprove: () => _handleApprove(request),
            onDeny: () => _handleDeny(request),
            onIgnore: _handleIgnore,
          ),
        ],
      ),
    );
  }
}
