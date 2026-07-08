package dev.micferna.antispam_app

import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import kotlin.concurrent.thread

/**
 * Bouton « Signaler comme spam » des notifications : envoie le
 * signalement au serveur du groupe sans ouvrir l'app.
 */
class ReportReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_REPORT) return
        val number = intent.getStringExtra(EXTRA_NUMBER) ?: return
        val notifId = intent.getIntExtra(EXTRA_NOTIFICATION_ID, 0)

        val prefs = context.getSharedPreferences(
            "FlutterSharedPreferences", Context.MODE_PRIVATE
        )
        val serverUrl = prefs.getString("flutter.server_url", null) ?: return
        val apiKey = prefs.getString("flutter.api_key", null) ?: return

        val pending = goAsync()
        thread {
            try {
                val conn = URL("$serverUrl/api/reports")
                    .openConnection() as HttpURLConnection
                conn.requestMethod = "POST"
                conn.doOutput = true
                conn.setRequestProperty("X-Api-Key", apiKey)
                conn.setRequestProperty("Content-Type", "application/json")
                conn.connectTimeout = 8000
                conn.readTimeout = 8000
                conn.outputStream.write(
                    JSONObject()
                        .put("number", number)
                        .put("category", "démarchage")
                        .toString()
                        .toByteArray()
                )
                conn.inputStream.close()
                conn.disconnect()
            } catch (_: Exception) {
                // Signalement perdu : l'utilisateur pourra le refaire depuis l'app.
            } finally {
                context.getSystemService(NotificationManager::class.java)
                    .cancel(notifId)
                pending.finish()
            }
        }
    }

    companion object {
        const val ACTION_REPORT = "dev.micferna.antispam_app.REPORT"
        const val EXTRA_NUMBER = "number"
        const val EXTRA_NOTIFICATION_ID = "notification_id"
    }
}
