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
 * Vérifie chaque appel entrant auprès du serveur du groupe, selon le
 * mode choisi dans l'app (préférence `screening_mode`) :
 *  - "alert"   : laisse sonner, notification si suspect (défaut) ;
 *  - "silence" : appel suspect → pas de sonnerie, il devient un appel
 *                manqué + notification ;
 *  - "block"   : appel suspect → rejeté immédiatement + notification.
 *
 * En modes silence/block, la décision attend la réponse du serveur
 * (~5 s max imposées par Android) ; serveur injoignable → l'appel
 * sonne normalement, on ne rate jamais un appel légitime.
 */
class SpamScreeningService : CallScreeningService() {

    override fun onScreenCall(callDetails: Call.Details) {
        val number = callDetails.handle?.schemeSpecificPart
        val prefs = getSharedPreferences("FlutterSharedPreferences", Context.MODE_PRIVATE)
        val serverUrl = prefs.getString("flutter.server_url", null)
        val apiKey = prefs.getString("flutter.api_key", null)
        val mode = prefs.getString("flutter.screening_mode", "alert") ?: "alert"

        if (number == null || serverUrl == null || apiKey == null) {
            respondToCall(callDetails, CallResponse.Builder().build())
            return
        }

        if (mode == "alert") {
            // Ne jamais retarder la sonnerie : on laisse passer tout de
            // suite, la notification arrive pendant que ça sonne.
            respondToCall(callDetails, CallResponse.Builder().build())
            thread {
                val json = lookup(serverUrl, apiKey, number) ?: return@thread
                if (json.optBoolean("suspicious")) notifySuspicious(json, mode)
                else notifyUnknown(json.optString("number", number))
            }
            return
        }

        // Modes silence / block : la réponse au système attend le verdict.
        thread {
            val json = lookup(serverUrl, apiKey, number)
            val suspicious = json?.optBoolean("suspicious") == true
            val response = when {
                !suspicious -> CallResponse.Builder().build()
                mode == "block" -> CallResponse.Builder()
                    .setDisallowCall(true)
                    .setRejectCall(true)
                    .build()
                else -> CallResponse.Builder()
                    .setSilenceCall(true)
                    .build()
            }
            respondToCall(callDetails, response)
            if (json == null) return@thread
            if (suspicious) notifySuspicious(json, mode)
            else notifyUnknown(json.optString("number", number))
        }
    }

    private fun lookup(serverUrl: String, apiKey: String, number: String): JSONObject? {
        return try {
            val encoded = URLEncoder.encode(number, "UTF-8")
            val conn = URL("$serverUrl/api/lookup/$encoded")
                .openConnection() as HttpURLConnection
            conn.setRequestProperty("X-Api-Key", apiKey)
            conn.connectTimeout = 2000
            conn.readTimeout = 2000
            val body = conn.inputStream.bufferedReader().readText()
            conn.disconnect()
            JSONObject(body)
        } catch (_: Exception) {
            null
        }
    }

    private fun notifySuspicious(json: JSONObject, mode: String) {
        val number = json.optString("number")
        val count = json.optInt("reportCount")
        val label = json.optString("importedLabel", "")
        val arcep = json.optBoolean("arcepDemarchage")

        val reason = buildList {
            if (count > 0) add("signalé par $count personne${if (count > 1) "s" else ""} du groupe")
            if (arcep) add("préfixe officiel de démarchage (ARCEP)")
            if (label.isNotEmpty() && !arcep) add(label)
        }.joinToString(" · ")

        val title = when (mode) {
            "block" -> "⛔ Appel bloqué : $number"
            "silence" -> "🔇 Appel silencié : $number"
            else -> "⚠️ Appel suspect : $number"
        }

        notify(
            number.hashCode(),
            channel(CHANNEL_ALERT, "Alertes spam", NotificationManager.IMPORTANCE_HIGH),
            title,
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
