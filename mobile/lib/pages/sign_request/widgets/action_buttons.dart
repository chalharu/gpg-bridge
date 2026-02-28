import 'package:flutter/material.dart';

/// Action buttons for the sign request page.
///
/// The approve button is disabled until GPG signing is implemented in KAN-47.
class ActionButtons extends StatelessWidget {
  const ActionButtons({
    super.key,
    required this.isSubmitting,
    required this.onDeny,
    required this.onIgnore,
  });

  final bool isSubmitting;
  final VoidCallback onDeny;
  final VoidCallback onIgnore;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Tooltip(
          message: 'GPG署名機能はKAN-47で実装予定',
          child: FilledButton.icon(
            onPressed: null, // Disabled until KAN-47
            icon: const Icon(Icons.check),
            label: const Text('承認'),
          ),
        ),
        const SizedBox(height: 8),
        OutlinedButton.icon(
          onPressed: isSubmitting ? null : onDeny,
          icon: const Icon(Icons.close),
          label: const Text('拒否'),
        ),
        const SizedBox(height: 8),
        TextButton(
          onPressed: isSubmitting ? null : onIgnore,
          child: const Text('無視'),
        ),
      ],
    );
  }
}
