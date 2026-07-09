import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'api.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  bool _night = false;
  int _start = 21;
  int _end = 8;
  List<String> _whitelist = [];
  final _add = TextEditingController();

  @override
  void initState() {
    super.initState();
    SharedPreferences.getInstance().then((p) {
      setState(() {
        _night = p.getBool(kPrefNightSilence) ?? false;
        _start = p.getInt(kPrefNightStart) ?? 21;
        _end = p.getInt(kPrefNightEnd) ?? 8;
        final raw = p.getString(kPrefWhitelist);
        if (raw != null) {
          _whitelist = (jsonDecode(raw) as List).map((e) => '$e').toList();
        }
      });
    });
  }

  Future<SharedPreferences> get _prefs => SharedPreferences.getInstance();

  Future<void> _saveNight() async {
    final p = await _prefs;
    await p.setBool(kPrefNightSilence, _night);
    await p.setInt(kPrefNightStart, _start);
    await p.setInt(kPrefNightEnd, _end);
  }

  Future<void> _saveWhitelist() async {
    final p = await _prefs;
    await p.setString(kPrefWhitelist, jsonEncode(_whitelist));
  }

  void _addNumber() {
    final n = _add.text.trim();
    if (n.isEmpty || _whitelist.contains(n)) return;
    setState(() {
      _whitelist.add(n);
      _add.clear();
    });
    _saveWhitelist();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Réglages avancés')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          SwitchListTile(
            value: _night,
            onChanged: (v) {
              setState(() => _night = v);
              _saveNight();
            },
            title: const Text('Ne pas déranger la nuit'),
            subtitle: const Text(
                'Les appels suspects sont silenciés la nuit, même en mode Alerter.'),
          ),
          if (_night)
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: Row(
                children: [
                  const Text('De '),
                  _hourPicker(_start, (h) {
                    setState(() => _start = h);
                    _saveNight();
                  }),
                  const Text('  à '),
                  _hourPicker(_end, (h) {
                    setState(() => _end = h);
                    _saveNight();
                  }),
                ],
              ),
            ),
          const Divider(height: 32),
          Text('Numéros toujours autorisés (whitelist)',
              style: Theme.of(context).textTheme.titleMedium),
          const Text(
              'Ces numéros ne sont jamais filtrés, même s\'ils sont signalés.'),
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _add,
                  keyboardType: TextInputType.phone,
                  decoration: const InputDecoration(
                    labelText: 'Numéro à autoriser',
                    border: OutlineInputBorder(),
                  ),
                ),
              ),
              const SizedBox(width: 8),
              FilledButton(onPressed: _addNumber, child: const Text('Ajouter')),
            ],
          ),
          const SizedBox(height: 8),
          if (_whitelist.isEmpty)
            const Padding(
              padding: EdgeInsets.all(12),
              child: Text('Aucun numéro autorisé pour l\'instant.'),
            ),
          ..._whitelist.map((n) => ListTile(
                leading: const Icon(Icons.verified_user, color: Colors.green),
                title: Text(n),
                trailing: IconButton(
                  icon: const Icon(Icons.delete_outline),
                  onPressed: () {
                    setState(() => _whitelist.remove(n));
                    _saveWhitelist();
                  },
                ),
              )),
        ],
      ),
    );
  }

  Widget _hourPicker(int value, ValueChanged<int> onChanged) {
    return DropdownButton<int>(
      value: value,
      items: [
        for (var h = 0; h < 24; h++)
          DropdownMenuItem(value: h, child: Text('${h}h')),
      ],
      onChanged: (h) => h != null ? onChanged(h) : null,
    );
  }
}
