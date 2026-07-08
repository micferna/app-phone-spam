package dev.micferna.antispam_app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.telecom.Call
import android.telecom.CallScreeningService
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import kotlin.concurrent.thread

/**
 * Vérifie chaque appel entrant auprès du serveur du groupe.
 * L'appel n'est jamais bloqué (mode « alerter + choix ») : on répond
 * immédiatement au système, puis on affiche une notification :
 *  - numéro suspect  → alerte forte « Spam signalé par N personnes »
 *  - numéro inconnu  → notification discrète avec bouton « Signaler »
 */
class SpamScreeningService : CallScreeningService() {

    override fun onScreenCall(callDetails: Call.Details) {
        // Ne jamais retarder la sonnerie : on laisse passer tout de suite.
        respondToCall(callDetails, CallResponse.Builder().build())

        val number = callDetails.handle?.schemeSpecificPart ?: return
        val prefs = getSharedPreferences("FlutterSharedPreferences", Context.MODE_PRIVATE)
        val serverUrl = prefs.getString("flutter.server_url", null) ?: return
        val apiKey = prefs.getString("flutter.api_key", null) ?: return

        thread {
            try {
                val encoded = URLEncoder.encode(number, "UTF-8")
                val conn = URL("$serverUrl/api/lookup/$encoded")
                    .openConnection() as HttpURLConnection
                conn.setRequestProperty("X-Api-Key", apiKey)
                conn.connectTimeout = 4000
                conn.readTimeout = 4000
                val body = conn.inputStream.bufferedReader().readText()
                conn.disconnect()

                val json = JSONObject(body)
                if (json.optBoolean("suspicious")) {
                    notifySuspicious(json)
                } else {
                    notifyUnknown(json.optString("number", number))
                }
            } catch (_: Exception) {
                // Serveur injoignable : on ne dérange pas l'utilisateur.
            }
        }
    }

    private fun notifySuspicious(json: JSONObject) {
        val number = json.optString("number")
        val count = json.optInt("reportCount")
        val label = json.optString("importedLabel", "")
        val arcep = json.optBoolean("arcepDemarchage")

        val reason = buildList {
            if (count > 0) add("signalé par $count personne${if (count > 1) "s" else ""} du groupe")
            if (arcep) add("préfixe officiel de démarchage (ARCEP)")
            if (label.isNotEmpty() && !arcep) add(label)
        }.joinToString(" · ")

        notify(
            number.hashCode(),
            channel(CHANNEL_ALERT, "Alertes spam", NotificationManager.IMPORTANCE_HIGH),
            "⚠️ Appel suspect : $number",
            reason.ifEmpty { "présent dans les listes de spam" },
            addReportAction = count == 0,
            number = number,
        )
    }

    private fun notifyUnknown(number: String) {
        notify(
            number.hashCode(),
            channel(CHANNEL_INFO, "Numéros inconnus", NotificationManager.IMPORTANCE_LOW),
            "Appel de $number",
            "Inconnu du groupe. C'était du démarchage ?",
            addReportAction = true,
            number = number,
        )
    }

    private fun channel(id: String, name: String, importance: Int): String {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(id, name, importance))
        return id
    }

    private fun notify(
        id: Int,
        channelId: String,
        title: String,
        text: String,
        addReportAction: Boolean,
        number: String,
    ) {
        val builder = Notification.Builder(this, channelId)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setAutoCancel(true)

        if (addReportAction) {
            val intent = Intent(this, ReportReceiver::class.java)
                .setAction(ReportReceiver.ACTION_REPORT)
                .putExtra(ReportReceiver.EXTRA_NUMBER, number)
                .putExtra(ReportReceiver.EXTRA_NOTIFICATION_ID, id)
            val pending = PendingIntent.getBroadcast(
                this, id, intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            builder.addAction(
                Notification.Action.Builder(null, "Signaler comme spam", pending).build()
            )
        }

        getSystemService(NotificationManager::class.java).notify(id, builder.build())
    }

    companion object {
        const val CHANNEL_ALERT = "spam_alert"
        const val CHANNEL_INFO = "unknown_call"
    }
}
