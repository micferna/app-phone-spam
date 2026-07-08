import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

/// Clés de configuration partagées avec le code natif Android :
/// le CallScreeningService Kotlin lit les mêmes valeurs dans
/// FlutterSharedPreferences (préfixe "flutter.").
const kPrefServerUrl = 'server_url';
const kPrefApiKey = 'api_key';
const kPrefScreeningMode = 'screening_mode'; // alert | silence | block
const kPrefSkipContacts = 'skip_contacts'; // bool (défaut true)
const kPrefCachedNumbers = 'cached_numbers'; // tableau JSON pour lookup offline

class LookupResult {
  final String number;
  final int reportCount;
  final List<String> categories;
  final String? importedLabel;
  final bool arcepDemarchage;
  final bool suspicious;

  LookupResult.fromJson(Map<String, dynamic> j)
      : number = j['number'] as String,
        reportCount = j['reportCount'] as int,
        categories = List<String>.from(j['categories'] ?? []),
        importedLabel = j['importedLabel'] as String?,
        arcepDemarchage = j['arcepDemarchage'] == true,
        suspicious = j['suspicious'] == true;
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
