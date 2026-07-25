package dev.micferna.antispam_app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * Vérification périodique des mises à jour, en arrière-plan.
 *
 * Sans ça, la bannière « nouvelle version » n'apparaît qu'à l'ouverture de
 * l'app — or c'est une app qu'on n'ouvre justement jamais : elle travaille
 * seule. Un correctif de sécurité pouvait donc rester non installé
 * indéfiniment sur un téléphone qui tourne pourtant tous les jours.
 *
 * Implémenté sur `JobScheduler` plutôt que WorkManager : le besoin est une
 * seule requête par jour, et WorkManager amènerait une dépendance lourde
 * (Room/SQLite) dans une chaîne de build déjà sensible (AGP 9). `setPersisted`
 * fait survivre la planification aux redémarrages.
 */
class UpdateCheckService : JobService() {

    override fun onStartJob(params: JobParameters?): Boolean {
        thread {
            try {
                checkAndNotify()
            } catch (_: Exception) {
                // Réseau absent, API GitHub indisponible : on retentera demain.
            }
            jobFinished(params, false)
        }
        return true // travail poursuivi hors du thread principal
    }

    /// Rien à annuler proprement : on laisse le système replanifier.
    override fun onStopJob(params: JobParameters?): Boolean = true

    private fun checkAndNotify() {
        val prefs = getSharedPreferences("FlutterSharedPreferences", Context.MODE_PRIVATE)
        // App jamais configurée = jamais utilisée : pas de notification.
        if (prefs.getString("flutter.server_url", null).isNullOrEmpty() ||
            prefs.getString("flutter.api_key", null).isNullOrEmpty()
        ) return

        val tag = latestTag() ?: return
        val installed = packageManager.getPackageInfo(packageName, 0).versionName ?: return
        if (!isNewer(tag.removePrefix("v"), installed)) return
        // Une seule notification par version publiée, pas une par exécution.
        if (prefs.getString(KEY_NOTIFIED, null) == tag) return

        notifyUpdate(tag)
        prefs.edit().putString(KEY_NOTIFIED, tag).apply()
    }

    private fun latestTag(): String? {
        val conn = URL("https://api.github.com/repos/$REPO/releases/latest")
            .openConnection() as HttpURLConnection
        return try {
            conn.setRequestProperty("Accept", "application/vnd.github+json")
            conn.connectTimeout = 10000
            conn.readTimeout = 10000
            if (conn.responseCode !in 200..299) return null
            JSONObject(conn.inputStream.bufferedReader().readText())
                .optString("tag_name")
                .ifEmpty { null }
        } finally {
            conn.disconnect()
        }
    }

    /// Compare deux versions « x.y.z » ; miroir de `_isNewer` côté Dart.
    private fun isNewer(a: String, b: String): Boolean {
        val pa = a.trim().split('.').map { it.toIntOrNull() ?: 0 }
        val pb = b.trim().split('.').map { it.toIntOrNull() ?: 0 }
        for (i in 0 until 3) {
            val va = pa.getOrElse(i) { 0 }
            val vb = pb.getOrElse(i) { 0 }
            if (va != vb) return va > vb
        }
        return false
    }

    private fun notifyUpdate(tag: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL, "Mises à jour", NotificationManager.IMPORTANCE_DEFAULT)
        )
        // L'appui ouvre l'app, qui propose l'installation en un tap.
        val open = packageManager.getLaunchIntentForPackage(packageName)
            ?.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val pi = PendingIntent.getActivity(
            this, 0, open ?: Intent(),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        nm.notify(
            CHANNEL.hashCode(),
            Notification.Builder(this, CHANNEL)
                .setSmallIcon(android.R.drawable.stat_sys_download)
                .setContentTitle("Mise à jour $tag disponible")
                .setContentText("Appuie pour l'installer — ta protection reste à jour.")
                .setContentIntent(pi)
                .setAutoCancel(true)
                .build()
        )
    }

    companion object {
        private const val REPO = "micferna/app-phone-spam"
        private const val CHANNEL = "update_available"
        /// Clé sans le préfixe « flutter. » : invisible côté Dart, qui n'a pas
        /// à connaître cet état purement natif.
        private const val KEY_NOTIFIED = "update_notified_tag"
        private const val JOB_ID = 4201

        /// Planifie la vérification quotidienne (idempotent). Appelé à chaque
        /// ouverture de l'app ; `setPersisted` la maintient ensuite même si
        /// l'utilisateur ne rouvre jamais l'app, redémarrages compris.
        fun schedule(ctx: Context) {
            val js = ctx.getSystemService(JobScheduler::class.java) ?: return
            if (js.getPendingJob(JOB_ID) != null) return
            js.schedule(
                JobInfo.Builder(JOB_ID, ComponentName(ctx, UpdateCheckService::class.java))
                    .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                    .setPeriodic(TimeUnit.DAYS.toMillis(1))
                    .setPersisted(true)
                    .build()
            )
        }
    }
}
