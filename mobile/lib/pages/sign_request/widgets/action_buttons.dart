import 'package:flutter/material.dart';

/// Action buttons for the sign request page.
class ActionButtons extends StatelessWidget {
  const ActionButtons({
    super.key,
    required this.isSubmitting,
    required this.onApprove,
    required this.onDeny,
    required this.onIgnore,
  });

  final bool isSubmitting;
  final VoidCallback onApprove;
  final VoidCallback onDeny;
  final VoidCallback onIgnore;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        FilledButton.icon(
          onPressed: isSubmitting ? null : onApprove,
          icon: const Icon(Icons.check),
          label: const Text('承認'),
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
