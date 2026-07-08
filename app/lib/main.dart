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
      TextEditingController(text: 'https://antispam-85e4a1d2.runship.fr');
  final _key = TextEditingController();
  String? _error;
  bool _busy = false;

  Future<void> _connect() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    final url = _url.text.trim().replaceAll(RegExp(r'/+$'), '');
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

  @override
  void initState() {
    super.initState();
    _refreshRole();
    _refreshList();
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
        title: const Text('Anti-Spam'),
        actions: [
          IconButton(
            icon: const Icon(Icons.logout),
            tooltip: 'Changer de compte',
            onPressed: _logout,
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _openReportSheet,
        icon: const Icon(Icons.report),
        label: const Text('Signaler'),
      ),
      body: RefreshIndicator(
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
