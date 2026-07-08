import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:antispam_app/main.dart';

void main() {
  testWidgets('l\'app démarre sur l\'écran de configuration',
      (WidgetTester tester) async {
    SharedPreferences.setMockInitialValues({});
    await tester.pumpWidget(const AntiSpamApp());
    await tester.pumpAndSettle();
    expect(find.text('Anti-Spam — Configuration'), findsOneWidget);
  });
}
