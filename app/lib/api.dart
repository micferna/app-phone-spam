import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

/// Clés de configuration partagées avec le code natif Android :
/// le CallScreeningService Kotlin lit les mêmes valeurs dans
/// FlutterSharedPreferences (préfixe "flutter.").
const kPrefServerUrl = 'server_url';
const kPrefApiKey = 'api_key';
const kPrefAdminKey = 'admin_key'; // stocké seulement sur l'appareil de l'admin
const kPrefScreeningMode = 'screening_mode'; // alert | silence | block
const kPrefSkipContacts = 'skip_contacts'; // bool (défaut true)
const kPrefCachedNumbers = 'cached_numbers'; // tableau JSON pour lookup offline
const kPrefSmsFilter = 'sms_filter'; // bool (défaut false) — détection SMS
const kPrefWhitelist = 'whitelist'; // tableau JSON de numéros jamais filtrés
const kPrefNightSilence = 'night_silence'; // bool — silence la nuit
const kPrefNightStart = 'night_start'; // int heure (défaut 21)
const kPrefNightEnd = 'night_end'; // int heure (défaut 8)
const kPrefHiddenMode = 'hidden_mode'; // ring | silence | block — numéros masqués
const kPrefAutoReport = 'auto_report'; // bool (défaut true) — signaler les blocages au groupe

const kRepoSlug = 'micferna/app-phone-spam';

/// Dernier tag de release publié sur GitHub (ex : "v1.2.0"), ou null.
Future<String?> latestReleaseTag() async {
  try {
    final res = await http
        .get(Uri.parse('https://api.github.com/repos/$kRepoSlug/releases/latest'),
            headers: {'Accept': 'application/vnd.github+json'})
        .timeout(const Duration(seconds: 6));
    if (res.statusCode != 200) return null;
    return jsonDecode(res.body)['tag_name'] as String?;
  } catch (_) {
    return null;
  }
}

/// URL de téléchargement direct de l'APK de la dernière release (premier asset
/// dont le nom finit par `.apk`), ou null si absent. Sert à l'updater intégré :
/// l'app télécharge et lance l'installateur elle-même, sans passer par le
/// navigateur ni un téléchargement manuel.
Future<String?> latestReleaseApkUrl() async {
  try {
    final res = await http
        .get(Uri.parse('https://api.github.com/repos/$kRepoSlug/releases/latest'),
            headers: {'Accept': 'application/vnd.github+json'})
        .timeout(const Duration(seconds: 8));
    if (res.statusCode != 200) return null;
    final assets = (jsonDecode(res.body)['assets'] as List?) ?? [];
    for (final a in assets) {
      final name = ((a as Map)['name'] as String?)?.toLowerCase() ?? '';
      if (name.endsWith('.apk')) {
        return a['browser_download_url'] as String?;
      }
    }
    return null;
  } catch (_) {
    return null;
  }
}

class LookupResult {
  final String number;
  final int reportCount;
  final List<String> categories;
  final String? importedLabel;
  final bool arcepDemarchage;
  final bool suspicious;
  final int suspicionScore;
  final bool campaignActive;
  final String? operatorName;
  final String lineType;
  final String lineLabel;
  final int lineRisk;

  LookupResult.fromJson(Map<String, dynamic> j)
      : number = j['number'] as String,
        reportCount = j['reportCount'] as int,
        categories = List<String>.from(j['categories'] ?? []),
        importedLabel = j['importedLabel'] as String?,
        arcepDemarchage = j['arcepDemarchage'] == true,
        suspicious = j['suspicious'] == true,
        suspicionScore = (j['suspicionScore'] ?? 0) as int,
        campaignActive = j['campaignActive'] == true,
        operatorName = j['operatorName'] as String?,
        lineType = (j['lineType'] ?? 'autre') as String,
        lineLabel = (j['lineLabel'] ?? '') as String,
        lineRisk = (j['lineRisk'] ?? 0) as int;
}

class GroupNumber {
  final String number;
  final int reportCount;
  final String? lastReport;

  GroupNumber.fromJson(Map<String, dynamic> j)
      : number = j['number'] as String,
        reportCount = j['reportCount'] as int,
        lastReport = j['lastReport'] as String?;
}

class ApiClient {
  final String baseUrl;
  final String apiKey;

  ApiClient(this.baseUrl, this.apiKey);

  /// Crée une invitation à usage unique (admin) → renvoie le token.
  Future<String> createInvite(String adminKey) async {
    final res = await http
        .post(_uri('/api/invites'), headers: {'X-Admin-Key': adminKey})
        .timeout(const Duration(seconds: 8));
    if (res.statusCode != 200) {
      throw Exception('Clé admin refusée (${res.statusCode})');
    }
    return jsonDecode(res.body)['token'] as String;
  }

  /// Consomme une invitation (nouveau membre, sans clé) → renvoie l'apiKey.
  static Future<String> redeemInvite(String url, String token, String name) async {
    final res = await http
        .post(Uri.parse('$url/api/invite/redeem'),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode({'token': token, 'name': name}))
        .timeout(const Duration(seconds: 8));
    if (res.statusCode != 200) {
      throw Exception(
          jsonDecode(res.body)['error'] ?? 'Invitation invalide (${res.statusCode})');
    }
    return jsonDecode(res.body)['apiKey'] as String;
  }

  static Future<ApiClient?> fromPrefs() async {
    final prefs = await SharedPreferences.getInstance();
    final url = prefs.getString(kPrefServerUrl);
    final key = prefs.getString(kPrefApiKey);
    if (url == null || key == null || url.isEmpty || key.isEmpty) return null;
    return ApiClient(url, key);
  }

  Map<String, String> get _headers => {
        'X-Api-Key': apiKey,
        'Content-Type': 'application/json',
      };

  Uri _uri(String path) => Uri.parse('$baseUrl$path');

  Future<bool> health() async {
    final res = await http
        .get(_uri('/api/health'))
        .timeout(const Duration(seconds: 8));
    return res.statusCode == 200;
  }

  /// Vérifie que la clé API est valide.
  Future<bool> checkAuth() async {
    final res = await http
        .get(_uri('/api/lookup/%2B33100000000'), headers: _headers)
        .timeout(const Duration(seconds: 8));
    return res.statusCode == 200;
  }

  Future<LookupResult> lookup(String number) async {
    final res = await http
        .get(_uri('/api/lookup/${Uri.encodeComponent(number)}'),
            headers: _headers)
        .timeout(const Duration(seconds: 8));
    if (res.statusCode != 200) throw Exception('Erreur ${res.statusCode}');
    return LookupResult.fromJson(jsonDecode(res.body));
  }

  Future<int> report(String number, {String? category, String? comment}) async {
    final res = await http
        .post(_uri('/api/reports'),
            headers: _headers,
            body: jsonEncode({
              'number': number,
              'category': category,
              'comment': comment,
            }))
        .timeout(const Duration(seconds: 8));
    if (res.statusCode != 200) {
      throw Exception(jsonDecode(res.body)['error'] ?? 'Erreur ${res.statusCode}');
    }
    return jsonDecode(res.body)['reportCount'] as int;
  }

  Future<void> unreport(String number) async {
    await http
        .delete(_uri('/api/reports/${Uri.encodeComponent(number)}'),
            headers: _headers)
        .timeout(const Duration(seconds: 8));
  }

  /// Retour « était-ce du spam ? » pour affiner le score et réduire les
  /// faux positifs.
  Future<void> feedback(String number, bool wasSpam) async {
    await http
        .post(_uri('/api/feedback'),
            headers: _headers,
            body: jsonEncode({'number': number, 'wasSpam': wasSpam}))
        .timeout(const Duration(seconds: 8));
  }

  /// Campagnes de démarchage actives (plages en pic de signalements).
  Future<List<String>> activeCampaigns() async {
    try {
      final res = await http
          .get(_uri('/api/alerts'), headers: _headers)
          .timeout(const Duration(seconds: 6));
      if (res.statusCode != 200) return [];
      final list = jsonDecode(res.body)['campaigns'] as List;
      return list.map((c) => '${c['prefix']}').toList();
    } catch (_) {
      return [];
    }
  }

  Future<List<GroupNumber>> groupNumbers() async {
    final res = await http
        .get(_uri('/api/numbers'), headers: _headers)
        .timeout(const Duration(seconds: 8));
    if (res.statusCode != 200) throw Exception('Erreur ${res.statusCode}');
    final body = jsonDecode(res.body);
    final community = body['community'] as List;
    final imported = (body['imported'] as List?) ?? [];

    // Cache hors-ligne : tous les numéros connus (communauté + importés)
    // → lus par le service natif pour un blocage instantané même sans réseau.
    final all = <String>{
      ...community.map((e) => e['number'] as String),
      ...imported.map((e) => e['number'] as String),
    };
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(kPrefCachedNumbers, jsonEncode(all.toList()));

    return community
        .map((e) => GroupNumber.fromJson(e as Map<String, dynamic>))
        .toList()
      ..sort((a, b) => (b.lastReport ?? '').compareTo(a.lastReport ?? ''));
  }
}
