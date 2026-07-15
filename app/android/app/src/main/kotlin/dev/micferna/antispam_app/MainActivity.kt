package dev.micferna.antispam_app

import android.app.NotificationManager
import android.app.role.RoleManager
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.core.content.FileProvider
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

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
                    // Depuis Android 14 (API 34), l'affichage plein écran par-dessus
                    // un appel entrant (l'écran rouge « anti-spam ») exige une
                    // autorisation spéciale « Notifications plein écran ». Sans elle,
                    // le système rétrograde silencieusement l'alerte en simple
                    // notification — c'est pour ça que l'écran rouge n'apparaît pas
                    // pendant la sonnerie, seulement quand on ouvre la notif.
                    "canUseFullScreenIntent" -> {
                        val ok = if (Build.VERSION.SDK_INT >= 34) {
                            getSystemService(NotificationManager::class.java)
                                .canUseFullScreenIntent()
                        } else {
                            true
                        }
                        result.success(ok)
                    }
                    "requestFullScreenIntent" -> {
                        if (Build.VERSION.SDK_INT >= 34) {
                            try {
                                startActivity(
                                    Intent(
                                        Settings.ACTION_MANAGE_APP_USE_FULL_SCREEN_INTENT,
                                        Uri.parse("package:$packageName")
                                    )
                                )
                            } catch (_: Exception) {
                                // Repli : réglages généraux de l'app.
                                startActivity(
                                    Intent(
                                        Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                                        Uri.parse("package:$packageName")
                                    )
                                )
                            }
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
                    // --- Mise à jour intégrée (sideload sans navigateur) ---
                    // L'app a-t-elle le droit d'installer des APK ? (« Installer
                    // des applis inconnues », à accorder une seule fois).
                    "canInstallPackages" -> {
                        val ok = if (Build.VERSION.SDK_INT >= 26) {
                            packageManager.canRequestPackageInstalls()
                        } else {
                            true
                        }
                        result.success(ok)
                    }
                    // Ouvre le réglage système pour accorder cette autorisation.
                    "requestInstallPermission" -> {
                        try {
                            startActivity(
                                Intent(
                                    Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                                    Uri.parse("package:$packageName")
                                )
                            )
                        } catch (_: Exception) {
                            startActivity(
                                Intent(
                                    Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                                    Uri.parse("package:$packageName")
                                )
                            )
                        }
                        result.success(null)
                    }
                    // Télécharge l'APK fourni puis lance l'installateur système.
                    // Le téléchargement est fait hors thread UI ; la réponse au
                    // canal MethodChannel doit repartir sur le thread principal.
                    "installUpdate" -> {
                        val url = (call.arguments as? Map<*, *>)?.get("url") as? String
                        if (url.isNullOrEmpty()) {
                            result.error("no_url", "URL de mise à jour manquante", null)
                        } else {
                            Thread {
                                try {
                                    val apk = downloadApk(url)
                                    if (!apkMatchesInstalledSigner(apk)) {
                                        apk.delete()
                                        throw SecurityException(
                                            "Mise à jour refusée : signature non reconnue"
                                        )
                                    }
                                    runOnUiThread {
                                        launchInstaller(apk)
                                        result.success("ok")
                                    }
                                } catch (e: Exception) {
                                    runOnUiThread {
                                        result.error("update_failed", e.message, null)
                                    }
                                }
                            }.start()
                        }
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

    /// Refuse toute URL de mise à jour hors HTTPS ou hors domaines GitHub.
    /// Appelée sur l'URL initiale ET chaque redirection : un attaquant capable
    /// d'injecter une redirection (ou un MITM) ne peut ni downgrader en http ni
    /// détourner le téléchargement vers un hôte tiers.
    private fun assertSafeUrl(u: URL) {
        require(u.protocol.equals("https", ignoreCase = true)) { "HTTPS obligatoire" }
        val host = u.host.lowercase().trimEnd('.')
        require(
            host == "github.com" ||
                host.endsWith(".github.com") ||
                host.endsWith(".githubusercontent.com")
        ) { "hôte non autorisé : $host" }
    }

    /// Télécharge l'APK vers le cache de l'app. Les redirections (GitHub renvoie
    /// vers un CDN) sont suivies manuellement et re-validées à chaque saut ;
    /// l'auto-follow est désactivé pour ne jamais suivre un saut non contrôlé.
    private fun downloadApk(url: String): File {
        var target = URL(url).also { assertSafeUrl(it) }
        var conn = (target.openConnection() as HttpURLConnection).apply {
            connectTimeout = 15000
            readTimeout = 30000
            instanceFollowRedirects = false
        }
        conn.connect()
        var redirects = 0
        while (conn.responseCode in 300..399 && redirects < 5) {
            val loc = conn.getHeaderField("Location") ?: break
            conn.disconnect()
            target = URL(target, loc).also { assertSafeUrl(it) }
            conn = (target.openConnection() as HttpURLConnection).apply {
                connectTimeout = 15000
                readTimeout = 30000
                instanceFollowRedirects = false
            }
            conn.connect()
            redirects++
        }
        if (conn.responseCode !in 200..299) {
            val code = conn.responseCode
            conn.disconnect()
            throw IOException("HTTP $code")
        }
        val file = File(cacheDir, "update.apk")
        if (file.exists()) file.delete()
        conn.inputStream.use { input ->
            file.outputStream().use { output -> input.copyTo(output) }
        }
        conn.disconnect()
        return file
    }

    /// Défense finale : n'installe l'APK que s'il s'agit bien d'une mise à jour
    /// de NOTRE app (même package) signée avec le MÊME certificat que la version
    /// installée. Ainsi, même si le transport était subverti, un APK malveillant
    /// (autre signataire) est rejeté avant l'installateur.
    private fun apkMatchesInstalledSigner(apk: File): Boolean {
        return try {
            val pm = packageManager
            val archive = pm.getPackageArchiveInfo(
                apk.absolutePath,
                PackageManager.GET_SIGNING_CERTIFICATES
            ) ?: return false
            if (archive.packageName != packageName) return false
            val installed = pm.getPackageInfo(
                packageName,
                PackageManager.GET_SIGNING_CERTIFICATES
            )
            val fromApk = archive.signingInfo?.apkContentsSigners ?: return false
            val fromApp = installed.signingInfo?.apkContentsSigners ?: return false
            val apkCerts = fromApk.map { sha256Hex(it.toByteArray()) }.toSet()
            val appCerts = fromApp.map { sha256Hex(it.toByteArray()) }.toSet()
            apkCerts.isNotEmpty() && apkCerts == appCerts
        } catch (_: Exception) {
            false
        }
    }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }

    /// Lance l'installateur système sur l'APK via un FileProvider (obligatoire
    /// depuis Android 7 pour partager un fichier avec le Package Installer).
    private fun launchInstaller(file: File) {
        val uri = FileProvider.getUriForFile(this, "$packageName.fileprovider", file)
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        startActivity(intent)
    }

    companion object {
        private const val REQUEST_ROLE = 1001
        private const val REQUEST_NOTIF = 1002
        private const val REQUEST_ANSWER = 1003
        private const val REQUEST_CONTACTS = 1004
        private const val REQUEST_SMS = 1005
    }
}
