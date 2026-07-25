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
// Synchro incrémentale de /api/numbers : horodatage + version de la liste
// renvoyés par la dernière synchro, et liste du groupe accumulée.
const kPrefGroupSince = 'group_since';
const kPrefGroupVersion = 'group_version';
const kPrefGroupCommunity = 'group_community';
// Racines ARCEP de démarchage servies par le serveur (lues par le natif).
const kPrefArcepPrefixes = 'arcep_prefixes';
const kPrefSmsFilter = 'sms_filter'; // bool (défaut false) — détection SMS
const kPrefWhitelist = 'whitelist'; // tableau JSON de numéros jamais filtrés
const kPrefNightSilence = 'night_silence'; // bool — silence la nuit
const kPrefNightStart = 'night_start'; // int heure (défaut 21)
const kPrefNightEnd = 'night_end'; // int heure (défaut 8)
const kPrefHiddenMode = 'hidden_mode'; // ring | silence | block — numéros masqués
const kPrefAutoReport = 'auto_report'; // bool (défaut true) — signaler les blocages au groupe
// Règles par catégorie de ligne (bool, défaut false), décision locale.
const kPrefBlockVoip = 'block_voip'; // VoIP / non-géographique (09)
const kPrefBlockIntl = 'block_intl'; // numéros internationaux
const kPrefBlockPremium = 'block_premium'; // surtaxés (08x, hors 080 vert)

const kRepoSlug = 'micferna/app-phone-spam';

/// Normalisation E.164 « best effort » (miroir de `toE164` côté Kotlin et de
/// `normalize_number` côté serveur). Sert à stocker la whitelist sous la même
/// forme que les numéros présentés par l'opérateur : saisir « 06 12 34 56 78 »
/// et recevoir « +33612345678 » doit désigner le même numéro.
String normalizeFr(String raw) {
  var n = raw.replaceAll(RegExp(r'[\s.\-()]'), '');
  if (n.startsWith('00')) n = '+${n.substring(2)}';
  if (n.length == 10 && n.startsWith('0') && n[1] != '0') {
    n = '+33${n.substring(1)}';
  }
  return n;
}

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

  /// Synchro de la liste du groupe, en incrémental.
  ///
  /// C'est de loin la plus grosse réponse de l'API et l'app la redemande à
  /// chaque ouverture. On renvoie au serveur l'horodatage et la version de la
  /// dernière synchro : il ne répond alors que ce qui a bougé, et on fusionne.
  /// Quand un numéro a été RETIRÉ de la liste, le serveur incrémente sa
  /// version et répond `full: true` — la liste reçue fait alors autorité et
  /// remplace le cache, sinon on garderait des numéros bloqués à tort.
  Future<List<GroupNumber>> groupNumbers() async {
    final prefs = await SharedPreferences.getInstance();
    final since = prefs.getString(kPrefGroupSince);
    final version = prefs.getInt(kPrefGroupVersion);

    var path = '/api/numbers';
    if (since != null && version != null) {
      path += '?since=${Uri.encodeQueryComponent(since)}&v=$version';
    }
    final res =
        await http.get(_uri(path), headers: _headers).timeout(const Duration(seconds: 8));
    if (res.statusCode != 200) throw Exception('Erreur ${res.statusCode}');
    final body = jsonDecode(res.body);
    final full = body['full'] != false; // serveur ancien sans le champ → complet

    // État accumulé : la communauté (affichée) indexée par numéro, et
    // l'ensemble de tous les numéros connus (communauté + listes importées)
    // que le service natif consulte pour bloquer hors-ligne.
    final community = <String, Map<String, dynamic>>{};
    final all = <String>{};
    if (!full) {
      final prev = prefs.getString(kPrefGroupCommunity);
      if (prev != null) {
        for (final e in jsonDecode(prev) as List) {
          community[e['number'] as String] = Map<String, dynamic>.from(e as Map);
        }
      }
      final prevAll = prefs.getString(kPrefCachedNumbers);
      if (prevAll != null) {
        all.addAll((jsonDecode(prevAll) as List).map((e) => '$e'));
      }
    }

    for (final e in body['community'] as List) {
      final entry = Map<String, dynamic>.from(e as Map);
      community[entry['number'] as String] = entry;
      all.add(entry['number'] as String);
    }
    for (final e in (body['imported'] as List?) ?? []) {
      all.add(e['number'] as String);
    }

    // Racines ARCEP servies par le serveur : le service natif les ajoute à sa
    // liste compilée. Permet de corriger la détection sans release de l'app.
    final arcep = (body['arcepPrefixes'] as List?)?.map((e) => '$e').toList();
    if (arcep != null && arcep.isNotEmpty) {
      await prefs.setString(kPrefArcepPrefixes, jsonEncode(arcep));
    }

    await prefs.setString(kPrefGroupCommunity, jsonEncode(community.values.toList()));
    await prefs.setString(kPrefCachedNumbers, jsonEncode(all.toList()));
    final syncedAt = body['syncedAt'] as String?;
    final listVersion = body['listVersion'] as int?;
    if (syncedAt != null && listVersion != null) {
      await prefs.setString(kPrefGroupSince, syncedAt);
      await prefs.setInt(kPrefGroupVersion, listVersion);
    }

    return community.values
        .map((e) => GroupNumber.fromJson(e))
        .toList()
      ..sort((a, b) => (b.lastReport ?? '').compareTo(a.lastReport ?? ''));
  }
}
