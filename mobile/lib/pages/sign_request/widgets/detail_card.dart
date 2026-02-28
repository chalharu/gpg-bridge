import 'package:flutter/material.dart';

import '../../../state/sign_request_state.dart';

/// Displays the sign request details (hash, algorithm, key ID).
class DetailCard extends StatelessWidget {
  const DetailCard({super.key, required this.request});

  final DecryptedSignRequest request;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('署名内容', style: Theme.of(context).textTheme.titleLarge),
            const SizedBox(height: 16),
            _buildRow(context, 'ハッシュアルゴリズム', request.hashAlgorithm),
            const SizedBox(height: 8),
            _buildRow(context, '鍵ID', request.keyId),
            const SizedBox(height: 8),
            _buildRow(context, 'ハッシュ値', request.hash),
          ],
        ),
      ),
    );
  }

  Widget _buildRow(BuildContext context, String label, String value) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: Theme.of(context).textTheme.labelSmall?.copyWith(
            color: Theme.of(context).colorScheme.onSurfaceVariant,
          ),
        ),
        const SizedBox(height: 2),
        SelectableText(
          value,
          style: Theme.of(
            context,
          ).textTheme.bodyMedium?.copyWith(fontFamily: 'monospace'),
        ),
      ],
    );
  }
}
