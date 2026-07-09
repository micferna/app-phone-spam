package dev.micferna.antispam_app

import android.app.role.RoleManager
import android.content.pm.PackageManager
import android.os.Build
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.io.File

class MainActivity : FlutterActivity() {
    private val channelName = "antispam/native"

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, channelName)
            .setMethodCallHandler { call, result ->
                val roleManager = getSystemService(RoleManager::class.java)
                when (call.method) {
                    "isRoleHeld" -> result.success(
                        roleManager.isRoleHeld(RoleManager.ROLE_CALL_SCREENING)
                    )
                    "requestRole" -> {
                        if (!roleManager.isRoleHeld(RoleManager.ROLE_CALL_SCREENING)) {
                            startActivityForResult(
                                roleManager.createRequestRoleIntent(RoleManager.ROLE_CALL_SCREENING),
                                REQUEST_ROLE
                            )
                        }
                        result.success(null)
                    }
                    "requestNotifPermission" -> {
                        if (Build.VERSION.SDK_INT >= 33 &&
                            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS)
                                != PackageManager.PERMISSION_GRANTED
                        ) {
                            requestPermissions(
                                arrayOf(android.Manifest.permission.POST_NOTIFICATIONS),
                                REQUEST_NOTIF
                            )
                        }
                        // Permet le bouton « Raccrocher » de l'écran d'alerte.
                        if (checkSelfPermission(android.Manifest.permission.ANSWER_PHONE_CALLS)
                            != PackageManager.PERMISSION_GRANTED
                        ) {
                            requestPermissions(
                                arrayOf(android.Manifest.permission.ANSWER_PHONE_CALLS),
                                REQUEST_ANSWER
                            )
                        }
                        result.success(null)
                    }
                    "requestContactsPermission" -> {
                        if (checkSelfPermission(android.Manifest.permission.READ_CONTACTS)
                            != PackageManager.PERMISSION_GRANTED
                        ) {
                            requestPermissions(
                                arrayOf(android.Manifest.permission.READ_CONTACTS),
                                REQUEST_CONTACTS
                            )
                        }
                        result.success(null)
                    }
                    "requestSmsPermission" -> {
                        if (checkSelfPermission(android.Manifest.permission.RECEIVE_SMS)
                            != PackageManager.PERMISSION_GRANTED
                        ) {
                            requestPermissions(
                                arrayOf(android.Manifest.permission.RECEIVE_SMS),
                                REQUEST_SMS
                            )
                        }
                        result.success(null)
                    }
                    "openUrl" -> {
                        val url = call.arguments as? String
                        if (url != null) {
                            startActivity(
                                android.content.Intent(
                                    android.content.Intent.ACTION_VIEW,
                                    android.net.Uri.parse(url)
                                ).addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
                            )
                        }
                        result.success(null)
                    }
                    "getHistory" -> {
                        val file = File(filesDir, History.FILE)
                        result.success(if (file.exists()) file.readText() else "")
                    }
                    "clearHistory" -> {
                        File(filesDir, History.FILE).delete()
                        result.success(null)
                    }
                    else -> result.notImplemented()
                }
            }
    }

    companion object {
        private const val REQUEST_ROLE = 1001
        private const val REQUEST_NOTIF = 1002
        private const val REQUEST_ANSWER = 1003
        private const val REQUEST_CONTACTS = 1004
        private const val REQUEST_SMS = 1005
    }
}
