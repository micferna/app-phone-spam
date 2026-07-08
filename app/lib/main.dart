import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'api.dart';

/// Canal vers le code natif Android : demande du rôle de filtrage
/// d'appels (ROLE_CALL_SCREENING) et de la permission notifications.
const _native = MethodChannel('antispam/native');

void main() => runApp(const AntiSpamApp());

class AntiSpamApp extends StatelessWidget {
  const AntiSpamApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Anti-Spam',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xFFD32F2F)),
        useMaterial3: true,
      ),
      home: const _Root(),
    );
  }
}

class _Root extends StatefulWidget {
  const _Root();

  @override
  State<_Root> createState() => _RootState();
}

class _RootState extends State<_Root> {
  ApiClient? _api;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    ApiClient.fromPrefs().then((api) {
      setState(() {
        _api = api;
        _loading = false;
      });
    });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }
    if (_api == null) {
      return SetupScreen(onDone: (api) => setState(() => _api = api));
    }
    return HomeScreen(
      api: _api!,
      onLogout: () => setState(() => _api = null),
    );
  }
}

// ---------------------------------------------------------------------------
// Écran de configuration : URL du serveur + clé API personnelle
// ---------------------------------------------------------------------------
class SetupScreen extends StatefulWidget {
  final void Function(ApiClient) onDone;

  const SetupScreen({super.key, required this.onDone});

  @override
  State<SetupScreen> createState() => _SetupScreenState();
}

class _SetupScreenState extends State<SetupScreen> {
  final _url =
      TextEditingController(text: 'https://antispam-03a9be84.runship.fr');
  final _key = TextEditingController();
  String? _error;
  bool _busy = false;

  Future<void> _connect() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    final url = _url.text.trim().replaceAll(RegExp(r'/+$'), '');
    if (!url.startsWith('https://')) {
      setState(() {
        _error = 'L\'adresse doit commencer par https:// (connexion chiffrée).';
        _busy = false;
      });
      return;
    }
    final api = ApiClient(url, _key.text.trim());
    try {
      if (!await api.checkAuth()) {
        setState(() => _error = 'Clé API refusée par le serveur.');
        return;
      }
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(kPrefServerUrl, url);
      await prefs.setString(kPrefApiKey, _key.text.trim());
      widget.onDone(api);
    } catch (e) {
      setState(() => _error = 'Connexion impossible : $e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Anti-Spam — Configuration')),
      body: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Text(
              'Renseigne l\'adresse du serveur du groupe et ta clé '
              'personnelle (demande-la à l\'admin).',
            ),
            const SizedBox(height: 20),
            TextField(
              controller: _url,
              decoration: const InputDecoration(
                labelText: 'Serveur',
                border: OutlineInputBorder(),
              ),
              keyboardType: TextInputType.url,
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _key,
              decoration: const InputDecoration(
                labelText: 'Clé API personnelle',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 20),
            if (_error != null)
              Padding(
                padding: const EdgeInsets.only(bottom: 12),
                child: Text(_error!,
                    style: TextStyle(
                        color: Theme.of(context).colorScheme.error)),
              ),
            FilledButton(
              onPressed: _busy ? null : _connect,
              child: _busy
                  ? const SizedBox(
                      height: 20,
                      width: 20,
                      child: CircularProgressIndicator(strokeWidth: 2))
                  : const Text('Se connecter'),
            ),
          ],
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Écran principal : protection, signalement, liste du groupe
// ---------------------------------------------------------------------------
class HomeScreen extends StatefulWidget {
  final ApiClient api;
  final VoidCallback onLogout;

  const HomeScreen({super.key, required this.api, required this.onLogout});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  bool _roleHeld = false;
  List<GroupNumber>? _numbers;
  String? _listError;
  String _mode = 'alert';
  bool _skipContacts = true;
  bool _smsFilter = false;
  int _tab = 0;

  static const _modeHelp = {
    'alert': 'Les appels suspects sonnent, avec une alerte '
        '« ⚠️ Signalé par N personnes » à l\'écran.',
    'silence': 'Les appels suspects ne sonnent pas : ils deviennent des '
        'appels manqués, avec le détail en notification.',
    'block': 'Les appels suspects sont rejetés direct (l\'appelant tombe '
        'sur ta messagerie). Notification en trace.',
  };

  @override
  void initState() {
    super.initState();
    _refreshRole();
    _refreshList();
    SharedPreferences.getInstance().then((p) {
      final m = p.getString(kPrefScreeningMode);
      final sc = p.getBool(kPrefSkipContacts) ?? true;
      final sms = p.getBool(kPrefSmsFilter) ?? false;
      if (mounted) {
        setState(() {
          if (m != null) _mode = m;
          _skipContacts = sc;
          _smsFilter = sms;
        });
      }
    });
  }

  Future<void> _setSmsFilter(bool v) async {
    setState(() => _smsFilter = v);
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(kPrefSmsFilter, v);
    if (v) {
      try {
        await _native.invokeMethod('requestSmsPermission');
      } catch (_) {}
    }
  }

  Future<void> _setMode(String mode) async {
    setState(() => _mode = mode);
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(kPrefScreeningMode, mode);
  }

  Future<void> _setSkipContacts(bool v) async {
    setState(() => _skipContacts = v);
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(kPrefSkipContacts, v);
    if (v) {
      try {
        await _native.invokeMethod('requestContactsPermission');
      } catch (_) {}
    }
  }

  Future<void> _refreshRole() async {
    try {
      final held = await _native.invokeMethod<bool>('isRoleHeld') ?? false;
      if (mounted) setState(() => _roleHeld = held);
    } on PlatformException {
      // iOS ou plateforme sans le canal natif : pas de filtrage temps réel.
    } on MissingPluginException {
      // idem
    }
  }

  Future<void> _requestRole() async {
    try {
      await _native.invokeMethod('requestNotifPermission');
      await _native.invokeMethod('requestRole');
    } catch (_) {
      // rôle indisponible sur cette plateforme
    }
    await _refreshRole();
  }

  Future<void> _refreshList() async {
    setState(() => _listError = null);
    try {
      final numbers = await widget.api.groupNumbers();
      if (mounted) setState(() => _numbers = numbers);
    } catch (e) {
      if (mounted) setState(() => _listError = '$e');
    }
  }

  Future<void> _openReportSheet() async {
    final reported = await showModalBottomSheet<bool>(
      context: context,
      isScrollControlled: true,
      builder: (_) => ReportSheet(api: widget.api),
    );
    if (reported == true) _refreshList();
  }

  Future<void> _logout() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(kPrefApiKey);
    widget.onLogout();
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Scaffold(
      appBar: AppBar(
        title: Text(_tab == 0 ? 'Anti-Spam' : 'Historique'),
        actions: [
          IconButton(
            icon: const Icon(Icons.logout),
            tooltip: 'Changer de compte',
            onPressed: _logout,
          ),
        ],
      ),
      floatingActionButton: _tab == 0
          ? FloatingActionButton.extended(
              onPressed: _openReportSheet,
              icon: const Icon(Icons.report),
              label: const Text('Signaler'),
            )
          : null,
      bottomNavigationBar: NavigationBar(
        selectedIndex: _tab,
        onDestinationSelected: (i) => setState(() => _tab = i),
        destinations: const [
          NavigationDestination(icon: Icon(Icons.shield), label: 'Protection'),
          NavigationDestination(icon: Icon(Icons.history), label: 'Historique'),
        ],
      ),
      body: IndexedStack(
        index: _tab,
        children: [
          _protectionTab(scheme),
          const HistoryTab(),
        ],
      ),
    );
  }

  Widget _protectionTab(ColorScheme scheme) {
    return RefreshIndicator(
      onRefresh: _refreshList,
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Card(
              color: _roleHeld ? scheme.primaryContainer : scheme.errorContainer,
              child: ListTile(
                leading: Icon(_roleHeld ? Icons.shield : Icons.shield_outlined),
                title: Text(
                    _roleHeld ? 'Protection active' : 'Protection inactive'),
                subtitle: Text(_roleHeld
                    ? 'Les appels entrants sont vérifiés en temps réel.'
                    : 'Autorise l\'app à filtrer les appels pour être '
                        'alerté pendant la sonnerie.'),
                trailing: _roleHeld
                    ? null
                    : FilledButton(
                        onPressed: _requestRole,
                        child: const Text('Activer'),
                      ),
              ),
            ),
            const SizedBox(height: 16),
            Text('Que faire des appels suspects ?',
                style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            SegmentedButton<String>(
              segments: const [
                ButtonSegment(
                    value: 'alert',
                    label: Text('Alerter'),
                    icon: Icon(Icons.notifications_active)),
                ButtonSegment(
                    value: 'silence',
                    label: Text('Silencieux'),
                    icon: Icon(Icons.notifications_off)),
                ButtonSegment(
                    value: 'block',
                    label: Text('Bloquer'),
                    icon: Icon(Icons.block)),
              ],
              selected: {_mode},
              onSelectionChanged: (s) => _setMode(s.first),
            ),
            const SizedBox(height: 8),
            Text(
              _modeHelp[_mode]!,
              style: Theme.of(context)
                  .textTheme
                  .bodySmall
                  ?.copyWith(color: Theme.of(context).colorScheme.outline),
            ),
            const SizedBox(height: 8),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              value: _skipContacts,
              onChanged: _setSkipContacts,
              title: const Text('Ne jamais filtrer mes contacts'),
              subtitle: const Text(
                  'Un numéro enregistré dans tes contacts sonne toujours '
                  'normalement (évite les faux positifs).'),
            ),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              value: _smsFilter,
              onChanged: _setSmsFilter,
              title: const Text('Détecter les SMS suspects'),
              subtitle: const Text(
                  'Analyse les SMS entrants (arnaques, faux colis, phishing) '
                  'et t\'alerte. Ne bloque pas le SMS (impossible sans être '
                  'l\'app SMS par défaut).'),
            ),
            const SizedBox(height: 16),
            Text('Numéros signalés par le groupe',
                style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            if (_listError != null)
              Text('Impossible de charger la liste : $_listError'),
            if (_numbers == null && _listError == null)
              const Center(
                  child: Padding(
                padding: EdgeInsets.all(24),
                child: CircularProgressIndicator(),
              )),
            if (_numbers != null && _numbers!.isEmpty)
              const Padding(
                padding: EdgeInsets.all(24),
                child: Text('Aucun signalement pour l\'instant. '
                    'Sois le premier à en ajouter un !'),
              ),
            if (_numbers != null)
              ..._numbers!.map((n) => ListTile(
                    leading: const Icon(Icons.phone_disabled),
                    title: Text(n.number),
                    subtitle: Text('Signalé par ${n.reportCount} personne'
                        '${n.reportCount > 1 ? 's' : ''}'),
                    trailing: IconButton(
                      icon: const Icon(Icons.undo),
                      tooltip: 'Retirer mon signalement',
                      onPressed: () async {
                        await widget.api.unreport(n.number);
                        _refreshList();
                      },
                    ),
                  )),
          ],
        ),
      );
  }
}

// ---------------------------------------------------------------------------
// Onglet Historique : journal des appels screenés (lu depuis le natif)
// ---------------------------------------------------------------------------
class HistoryTab extends StatefulWidget {
  const HistoryTab({super.key});

  @override
  State<HistoryTab> createState() => _HistoryTabState();
}

class _HistoryTabState extends State<HistoryTab> {
  List<Map<String, dynamic>>? _entries;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final raw = await _native.invokeMethod<String>('getHistory') ?? '';
      final entries = raw
          .split('\n')
          .where((l) => l.trim().isNotEmpty)
          .map((l) => jsonDecode(l) as Map<String, dynamic>)
          .toList()
          .reversed
          .toList();
      if (mounted) setState(() => _entries = entries);
    } catch (_) {
      if (mounted) setState(() => _entries = []);
    }
  }

  Future<void> _clear() async {
    try {
      await _native.invokeMethod('clearHistory');
    } catch (_) {}
    _load();
  }

  ({IconData icon, Color color, String label}) _style(
      String kind, String verdict, String action) {
    if (kind == 'sms') {
      return (icon: Icons.sms_failed, color: Colors.red, label: 'SMS suspect');
    }
    if (action == 'bloqué') return (icon: Icons.block, color: Colors.red, label: 'Bloqué');
    if (action == 'silencié') {
      return (icon: Icons.notifications_off, color: Colors.orange, label: 'Silencié');
    }
    if (verdict == 'suspect') {
      return (icon: Icons.warning, color: Colors.orange, label: 'Alerté');
    }
    if (verdict == 'contact') {
      return (icon: Icons.person, color: Colors.green, label: 'Contact');
    }
    return (icon: Icons.call, color: Colors.grey, label: 'Laissé sonner');
  }

  String _time(int ms) {
    final d = DateTime.fromMillisecondsSinceEpoch(ms);
    String two(int n) => n.toString().padLeft(2, '0');
    return '${two(d.day)}/${two(d.month)} ${two(d.hour)}:${two(d.minute)}';
  }

  @override
  Widget build(BuildContext context) {
    final entries = _entries;
    if (entries == null) {
      return const Center(child: CircularProgressIndicator());
    }
    if (entries.isEmpty) {
      return RefreshIndicator(
        onRefresh: _load,
        child: ListView(
          children: const [
            SizedBox(height: 120),
            Center(
              child: Padding(
                padding: EdgeInsets.all(24),
                child: Text('Aucun appel enregistré pour l\'instant.\n'
                    'Le journal se remplira au fil des appels entrants.',
                    textAlign: TextAlign.center),
              ),
            ),
          ],
        ),
      );
    }
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        itemCount: entries.length + 1,
        itemBuilder: (context, i) {
          if (i == 0) {
            return Padding(
              padding: const EdgeInsets.fromLTRB(16, 12, 16, 0),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Text('${entries.length} appel${entries.length > 1 ? 's' : ''}',
                      style: Theme.of(context).textTheme.titleSmall),
                  TextButton.icon(
                    onPressed: _clear,
                    icon: const Icon(Icons.delete_outline, size: 18),
                    label: const Text('Vider'),
                  ),
                ],
              ),
            );
          }
          final e = entries[i - 1];
          final st = _style('${e['kind'] ?? 'call'}', '${e['verdict']}', '${e['action']}');
          final op = '${e['operator'] ?? ''}';
          return ListTile(
            leading: Icon(st.icon, color: st.color),
            title: Text('${e['number']}'),
            subtitle: Text([
              st.label,
              if (op.isNotEmpty) 'opérateur : $op',
            ].join(' · ')),
            trailing: Text(_time((e['ts'] as num).toInt()),
                style: Theme.of(context).textTheme.bodySmall),
          );
        },
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Feuille de signalement
// ---------------------------------------------------------------------------
class ReportSheet extends StatefulWidget {
  final ApiClient api;

  const ReportSheet({super.key, required this.api});

  @override
  State<ReportSheet> createState() => _ReportSheetState();
}

class _ReportSheetState extends State<ReportSheet> {
  final _number = TextEditingController();
  final _comment = TextEditingController();
  static const _categories = [
    'démarchage', 'arnaque', 'énergie', 'CPF', 'assurance', 'autre',
  ];
  String _category = 'démarchage';
  String? _error;
  bool _busy = false;

  Future<void> _send() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final count = await widget.api.report(
        _number.text,
        category: _category,
        comment: _comment.text.isEmpty ? null : _comment.text,
      );
      if (!mounted) return;
      Navigator.pop(context, true);
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
        content: Text('Numéro signalé — $count signalement'
            '${count > 1 ? 's' : ''} au total dans le groupe.'),
      ));
    } catch (e) {
      setState(() => _error = '$e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: EdgeInsets.only(
        left: 20,
        right: 20,
        top: 20,
        bottom: MediaQuery.of(context).viewInsets.bottom + 20,
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text('Signaler un numéro',
              style: Theme.of(context).textTheme.titleLarge),
          const SizedBox(height: 16),
          TextField(
            controller: _number,
            decoration: const InputDecoration(
              labelText: 'Numéro (ex : 06 12 34 56 78)',
              border: OutlineInputBorder(),
            ),
            keyboardType: TextInputType.phone,
            autofocus: true,
          ),
          const SizedBox(height: 12),
          Wrap(
            spacing: 8,
            children: _categories
                .map((c) => ChoiceChip(
                      label: Text(c),
                      selected: _category == c,
                      onSelected: (_) => setState(() => _category = c),
                    ))
                .toList(),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _comment,
            decoration: const InputDecoration(
              labelText: 'Commentaire (facultatif)',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 16),
          if (_error != null)
            Padding(
              padding: const EdgeInsets.only(bottom: 12),
              child: Text(_error!,
                  style:
                      TextStyle(color: Theme.of(context).colorScheme.error)),
            ),
          FilledButton(
            onPressed: _busy ? null : _send,
            child: const Text('Envoyer au groupe'),
          ),
        ],
      ),
    );
  }
}
