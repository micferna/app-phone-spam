package dev.micferna.antispam_app

import android.app.role.RoleManager
import android.content.pm.PackageManager
import android.os.Build
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

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
                        result.success(null)
                    }
                    else -> result.notImplemented()
                }
            }
    }

    companion object {
        private const val REQUEST_ROLE = 1001
        private const val REQUEST_NOTIF = 1002
    }
}
