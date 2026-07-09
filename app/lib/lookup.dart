import 'package:flutter/material.dart';

import 'api.dart';

/// Écran « Vérifier un numéro » : interroge le groupe + l'analyse déterministe
/// du backend (type de ligne, plage ARCEP, opérateur, campagne). 100% local au
/// serveur du groupe — aucun numéro n'est envoyé à un tiers.
class LookupScreen extends StatefulWidget {
  final ApiClient api;
  const LookupScreen({super.key, required this.api});

  @override
  State<LookupScreen> createState() => _LookupScreenState();
}

class _LookupScreenState extends State<LookupScreen> {
  final _ctrl = TextEditingController();
  LookupResult? _result;
  String? _error;
  bool _busy = false;

  Future<void> _search() async {
    final q = _ctrl.text.trim();
    if (q.isEmpty) return;
    FocusScope.of(context).unfocus();
    setState(() {
      _busy = true;
      _error = null;
      _result = null;
    });
    try {
      final r = await widget.api.lookup(q);
      if (mounted) setState(() => _result = r);
    } catch (_) {
      if (mounted) {
        setState(() => _error =
            'Numéro introuvable ou format invalide (ex : 06 12 34 56 78).');
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Color _riskColor(int risk, ColorScheme s) => switch (risk) {
        >= 3 => s.error,
        2 => Colors.deepOrange,
        1 => Colors.orange,
        _ => s.onSurfaceVariant,
      };

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Scaffold(
      appBar: AppBar(title: const Text('Vérifier un numéro')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          TextField(
            controller: _ctrl,
            keyboardType: TextInputType.phone,
            autofocus: true,
            textInputAction: TextInputAction.search,
            onSubmitted: (_) => _search(),
            decoration: InputDecoration(
              labelText: 'Numéro à vérifier',
              hintText: '06 12 34 56 78',
              border: const OutlineInputBorder(),
              prefixIcon: const Icon(Icons.search),
              suffixIcon: IconButton(
                icon: const Icon(Icons.arrow_forward),
                onPressed: _busy ? null : _search,
              ),
            ),
          ),
          const SizedBox(height: 16),
          if (_busy) const Center(child: CircularProgressIndicator()),
          if (_error != null)
            Card(
              color: scheme.surfaceContainerHighest,
              child: ListTile(
                leading: const Icon(Icons.help_outline),
                title: Text(_error!),
              ),
            ),
          if (_result != null) _resultView(_result!, scheme),
        ],
      ),
    );
  }

  Widget _resultView(LookupResult r, ColorScheme scheme) {
    final danger = r.suspicious;
    final headColor = danger ? scheme.errorContainer : Colors.green.shade100;
    final headFg = danger ? scheme.onErrorContainer : Colors.green.shade900;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Card(
          color: headColor,
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Icon(danger ? Icons.warning_amber : Icons.verified_user,
                        color: headFg),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        danger ? 'Numéro à risque' : 'Rien de signalé',
                        style: TextStyle(
                            color: headFg,
                            fontWeight: FontWeight.bold,
                            fontSize: 18),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 4),
                Text(r.number,
                    style: TextStyle(color: headFg, fontFamily: 'monospace')),
                const SizedBox(height: 12),
                // Barre de score de risque.
                ClipRRect(
                  borderRadius: BorderRadius.circular(6),
                  child: LinearProgressIndicator(
                    value: (r.suspicionScore.clamp(0, 100)) / 100,
                    minHeight: 8,
                    backgroundColor: Colors.black12,
                    color: headFg,
                  ),
                ),
                const SizedBox(height: 4),
                Text('Score de risque : ${r.suspicionScore}/100',
                    style: TextStyle(color: headFg, fontSize: 12)),
              ],
            ),
          ),
        ),
        Card(
          child: Column(
            children: [
              _row(Icons.groups, 'Signalé par le groupe',
                  '${r.reportCount} personne${r.reportCount > 1 ? 's' : ''}'),
              _row(
                Icons.dialpad,
                'Type de ligne',
                r.lineLabel,
                color: _riskColor(r.lineRisk, scheme),
              ),
              if (r.operatorName != null && r.operatorName!.isNotEmpty)
                _row(Icons.cell_tower, 'Opérateur', r.operatorName!),
              if (r.campaignActive)
                _row(Icons.campaign, 'Campagne en cours',
                    'Pic de signalements sur cette plage (24 h)',
                    color: scheme.error),
              if (r.arcepDemarchage)
                _row(Icons.gavel, 'Plage ARCEP',
                    'Réservée au démarchage téléphonique',
                    color: scheme.error),
              if (r.importedLabel != null && r.importedLabel!.isNotEmpty)
                _row(Icons.list_alt, 'Liste publique', r.importedLabel!),
              if (r.categories.isNotEmpty)
                Padding(
                  padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
                  child: Align(
                    alignment: Alignment.centerLeft,
                    child: Wrap(
                      spacing: 6,
                      runSpacing: 6,
                      children: r.categories
                          .map((c) => Chip(
                                label: Text(c),
                                visualDensity: VisualDensity.compact,
                              ))
                          .toList(),
                    ),
                  ),
                ),
            ],
          ),
        ),
        const SizedBox(height: 8),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 8),
          child: Text(
            'Analyse locale au serveur du groupe (type de ligne, plage ARCEP, '
            'opérateur) + signalements des membres. Aucun numéro envoyé à un tiers.',
            style: TextStyle(
                color: scheme.onSurfaceVariant, fontSize: 12),
          ),
        ),
      ],
    );
  }

  Widget _row(IconData icon, String label, String value, {Color? color}) {
    return ListTile(
      dense: true,
      leading: Icon(icon, color: color),
      title: Text(label, style: const TextStyle(fontSize: 13)),
      subtitle: Text(value,
          style: TextStyle(
              fontSize: 15,
              color: color,
              fontWeight: color != null ? FontWeight.w600 : null)),
    );
  }
}
