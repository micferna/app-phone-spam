package dev.micferna.antispam_app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import kotlin.concurrent.thread

/**
 * Tuile « Réglages rapides » : signale au groupe le dernier appel filtré, sans
 * ouvrir l'app.
 *
 * Comble le trou du parcours existant : le bouton « Signaler » ne vit que dans
 * la notification de l'appel. Une fois celle-ci balayée, il fallait rouvrir
 * l'app et retaper le numéro. Depuis le volet des réglages rapides, c'est un
 * geste — y compris plusieurs minutes après l'appel.
 *
 * Le numéro vient du journal local (History), donc aucune permission de lecture
 * du journal d'appels système n'est nécessaire.
 */
class ReportTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        val tile = qsTile ?: return
        val number = History.lastCallNumber(this)
        tile.state = if (number == null) Tile.STATE_UNAVAILABLE else Tile.STATE_INACTIVE
        tile.label = "Signaler l'appel"
        if (Build.VERSION.SDK_INT >= 29) {
            tile.subtitle = number ?: "aucun appel récent"
        }
        tile.updateTile()
    }

    override fun onClick() {
        super.onClick()
        val number = History.lastCallNumber(this)
        if (number == null) {
            notify("Rien à signaler", "Aucun appel récent dans le journal de l'app.")
            return
        }
        val prefs = getSharedPreferences("FlutterSharedPreferences", Context.MODE_PRIVATE)
        val serverUrl = prefs.getString("flutter.server_url", null)
        val apiKey = prefs.getString("flutter.api_key", null)
        if (serverUrl == null || apiKey == null) {
            notify("Signalement impossible", "Connecte-toi au serveur du groupe dans l'app.")
            return
        }

        // La tuile passe brièvement en « actif » : sans retour visuel immédiat,
        // rien ne distingue un appui pris en compte d'un appui manqué.
        qsTile?.let {
            it.state = Tile.STATE_ACTIVE
            it.updateTile()
        }

        thread {
            val ok = postReport(serverUrl, apiKey, number)
            if (ok) {
                History.log(this, "report", number, "signalé", "signalé comme spam", "")
                notify("Signalé au groupe ✅", "$number remonté comme démarchage.")
            } else {
                notify("Signalement échoué", "$number n'a pas pu être envoyé. Réessaie depuis l'app.")
            }
            qsTile?.let {
                it.state = Tile.STATE_INACTIVE
                it.updateTile()
            }
        }
    }

    private fun postReport(serverUrl: String, apiKey: String, number: String): Boolean {
        return try {
            val conn = URL("$serverUrl/api/reports").openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.setRequestProperty("X-Api-Key", apiKey)
            conn.setRequestProperty("Content-Type", "application/json")
            conn.connectTimeout = 8000
            conn.readTimeout = 8000
            conn.outputStream.use {
                it.write(
                    JSONObject()
                        .put("number", number)
                        .put("category", "démarchage")
                        .put("comment", "signalé depuis les réglages rapides")
                        .toString()
                        .toByteArray(Charsets.UTF_8)
                )
            }
            val code = conn.responseCode
            conn.disconnect()
            code in 200..299
        } catch (_: Exception) {
            false
        }
    }

    private fun notify(title: String, text: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL, "Signalements", NotificationManager.IMPORTANCE_LOW)
        )
        nm.notify(
            CHANNEL.hashCode(),
            Notification.Builder(this, CHANNEL)
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentTitle(title)
                .setContentText(text)
                .setAutoCancel(true)
                .build()
        )
    }

    companion object {
        private const val CHANNEL = "quick_report"
    }
}
