import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'api.dart';

// ---------------------------------------------------------------------------
// Côté admin : génère un QR d'invitation à usage unique
// ---------------------------------------------------------------------------
class InviteScreen extends StatefulWidget {
  final ApiClient api;

  const InviteScreen({super.key, required this.api});

  @override
  State<InviteScreen> createState() => _InviteScreenState();
}

class _InviteScreenState extends State<InviteScreen> {
  final _adminKey = TextEditingController();
  String? _qrData;
  String? _error;
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    SharedPreferences.getInstance().then((p) {
      final k = p.getString(kPrefAdminKey);
      if (k != null) _adminKey.text = k;
    });
  }

  Future<void> _generate() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final token = await widget.api.createInvite(_adminKey.text.trim());
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(kPrefAdminKey, _adminKey.text.trim());
      setState(() {
        _qrData = jsonEncode({'url': widget.api.baseUrl, 'invite': token});
      });
    } catch (e) {
      setState(() => _error = '$e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Inviter un membre')),
      body: Padding(
        padding: const EdgeInsets.all(20),
        child: _qrData == null
            ? Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const Text(
                      'Entre ta clé admin pour générer une invitation à usage '
                      'unique (valable 7 jours). Le nouveau membre la scanne '
                      'depuis son écran de connexion.'),
                  const SizedBox(height: 16),
                  TextField(
                    controller: _adminKey,
                    obscureText: true,
                    decoration: const InputDecoration(
                        labelText: 'Clé admin', border: OutlineInputBorder()),
                  ),
                  const SizedBox(height: 16),
                  if (_error != null)
                    Padding(
                      padding: const EdgeInsets.only(bottom: 12),
                      child: Text(_error!,
                          style: TextStyle(
                              color: Theme.of(context).colorScheme.error)),
                    ),
                  FilledButton(
                    onPressed: _busy ? null : _generate,
                    child: _busy
                        ? const SizedBox(
                            height: 20,
                            width: 20,
                            child: CircularProgressIndicator(strokeWidth: 2))
                        : const Text('Générer le QR'),
                  ),
                ],
              )
            : Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Container(
                    padding: const EdgeInsets.all(16),
                    color: Colors.white,
                    child: QrImageView(data: _qrData!, size: 260),
                  ),
                  const SizedBox(height: 20),
                  const Text(
                    'Fais scanner ce QR au nouveau membre depuis l\'écran de '
                    'connexion de l\'app. Usage unique.',
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 20),
                  OutlinedButton(
                    onPressed: () => setState(() => _qrData = null),
                    child: const Text('Générer une autre invitation'),
                  ),
                ],
              ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Côté nouveau membre : scanne le QR → demande le prénom → consomme
// l'invitation → renvoie {url, key}
// ---------------------------------------------------------------------------
class ScanInviteScreen extends StatefulWidget {
  const ScanInviteScreen({super.key});

  @override
  State<ScanInviteScreen> createState() => _ScanInviteScreenState();
}

class _ScanInviteScreenState extends State<ScanInviteScreen> {
  bool _handling = false;

  Future<void> _onDetect(BarcodeCapture capture) async {
    if (_handling) return;
    final raw = capture.barcodes.firstOrNull?.rawValue;
    if (raw == null) return;
    Map<String, dynamic> payload;
    try {
      payload = jsonDecode(raw) as Map<String, dynamic>;
      if (payload['url'] == null || payload['invite'] == null) return;
    } catch (_) {
      return; // pas un QR d'invitation
    }
    // Le QR est le bootstrap de confiance : on refuse toute URL non https
    // (sinon un QR hostile détournerait prénom + token, puis tous les lookups
    // — numéros des appelants — vers le serveur de l'attaquant).
    final url = '${payload['url']}';
    if (!url.startsWith('https://')) {
      setState(() => _handling = true);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
          content: Text('Invitation refusée : le serveur doit être en HTTPS.'),
        ));
      }
      setState(() => _handling = false);
      return;
    }
    setState(() => _handling = true);

    final name = await _askName();
    if (name == null || name.isEmpty) {
      setState(() => _handling = false);
      return;
    }
    try {
      final key = await ApiClient.redeemInvite(url, '${payload['invite']}', name);
      if (mounted) {
        Navigator.pop(context, {'url': url, 'key': key});
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('$e')));
        setState(() => _handling = false);
      }
    }
  }

  Future<String?> _askName() {
    final ctrl = TextEditingController();
    return showDialog<String>(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Ton prénom / pseudo'),
        content: TextField(
          controller: ctrl,
          autofocus: true,
          decoration: const InputDecoration(hintText: 'Prénom'),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Annuler')),
          FilledButton(
              onPressed: () => Navigator.pop(context, ctrl.text.trim()),
              child: const Text('Rejoindre')),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Scanner l\'invitation')),
      body: Stack(
        alignment: Alignment.center,
        children: [
          MobileScanner(onDetect: _onDetect),
          if (_handling) const CircularProgressIndicator(),
          if (!_handling)
            const Positioned(
              bottom: 40,
              child: Text('Vise le QR d\'invitation',
                  style: TextStyle(color: Colors.white, fontSize: 16)),
            ),
        ],
      ),
    );
  }
}
