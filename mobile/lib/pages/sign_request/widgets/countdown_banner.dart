import 'package:flutter/material.dart';

/// Displays a countdown timer banner that turns red when < 60 seconds remain.
class CountdownBanner extends StatelessWidget {
  const CountdownBanner({
    super.key,
    required this.timerText,
    required this.remaining,
  });

  final String timerText;
  final Duration remaining;

  @override
  Widget build(BuildContext context) {
    final isUrgent = remaining.inSeconds < 60;
    final color = isUrgent
        ? Theme.of(context).colorScheme.error
        : Theme.of(context).colorScheme.primary;

    return Card(
      color: color.withValues(alpha: 0.1),
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 16),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.timer, color: color),
            const SizedBox(width: 8),
            Text(
              '残り時間: $timerText',
              style: Theme.of(context).textTheme.titleMedium?.copyWith(
                color: color,
                fontWeight: FontWeight.bold,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
