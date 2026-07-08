package dev.micferna.antispam_app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.ContactsContract
import android.telecom.Call
import android.telecom.CallScreeningService
import org.json.JSONArray
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
        val skipContacts = prefs.getBoolean("flutter.skip_contacts", true)

        if (number == null || serverUrl == null || apiKey == null) {
            respondToCall(callDetails, CallResponse.Builder().build())
            return
        }

        // Exemption des contacts : un numéro connu n'est jamais filtré.
        if (skipContacts && isInContacts(number)) {
            respondToCall(callDetails, CallResponse.Builder().build())
            logHistory(number, "contact", "laissé sonner", "")
            return
        }

        if (mode == "alert") {
            // Ne jamais retarder la sonnerie : on laisse passer tout de
            // suite, la notification arrive pendant que ça sonne.
            respondToCall(callDetails, CallResponse.Builder().build())
            thread {
                val json = lookup(serverUrl, apiKey, number)
                if (json != null && json.optBoolean("suspicious")) {
                    notifySuspicious(json, mode)
                    logHistory(number, "suspect", "alerte", operatorLabel(json))
                } else {
                    notifyUnknown(json?.optString("number", number) ?: number)
                    logHistory(number, "inconnu", "laissé sonner", "")
                }
            }
            return
        }

        // Modes silence / block : la réponse au système attend le verdict.
        thread {
            val json = lookup(serverUrl, apiKey, number)
            // Serveur injoignable → repli sur le cache hors-ligne.
            val suspicious = json?.optBoolean("suspicious") == true ||
                (json == null && cachedSuspicious(prefs, number))
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
            val action = when {
                !suspicious -> "laissé sonner"
                mode == "block" -> "bloqué"
                else -> "silencié"
            }
            val verdict = if (suspicious) "suspect" else "inconnu"
            if (json != null && json.optBoolean("suspicious")) notifySuspicious(json, mode)
            else if (!suspicious) notifyUnknown(json?.optString("number", number) ?: number)
            logHistory(number, verdict, action, json?.let { operatorLabel(it) } ?: "")
        }
    }

    // --- Exemption des contacts ---
    private fun isInContacts(number: String): Boolean {
        if (checkSelfPermission(android.Manifest.permission.READ_CONTACTS)
            != PackageManager.PERMISSION_GRANTED
        ) return false
        return try {
            val uri = Uri.withAppendedPath(
                ContactsContract.PhoneLookup.CONTENT_FILTER_URI, Uri.encode(number)
            )
            contentResolver.query(uri, arrayOf(ContactsContract.PhoneLookup._ID), null, null, null)
                ?.use { it.count > 0 } ?: false
        } catch (_: Exception) {
            false
        }
    }

    // --- Cache hors-ligne : la liste des numéros suspects synchronisée par
    // l'app (préférence flutter.cached_numbers = tableau JSON de numéros). ---
    private fun cachedSuspicious(prefs: android.content.SharedPreferences, number: String): Boolean {
        val raw = prefs.getString("flutter.cached_numbers", null) ?: return false
        return try {
            val arr = JSONArray(raw)
            (0 until arr.length()).any { arr.optString(it) == number }
        } catch (_: Exception) {
            false
        }
    }

    private fun operatorLabel(json: JSONObject): String {
        val name = if (json.isNull("operatorName")) "" else json.optString("operatorName", "")
        return if (name.isNotEmpty()) name else if (json.isNull("operator")) "" else json.optString("operator", "")
    }

    private fun logHistory(number: String, verdict: String, action: String, operator: String) {
        History.log(this, "call", number, verdict, action, operator)
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

        val operatorName = if (json.isNull("operatorName")) "" else json.optString("operatorName", "")
        val operator = if (json.isNull("operator")) "" else json.optString("operator", "")
        val reason = buildList {
            if (count > 0) add("signalé par $count personne${if (count > 1) "s" else ""} du groupe")
            if (arcep) add("préfixe officiel de démarchage (ARCEP)")
            if (label.isNotEmpty() && !arcep) add(label)
            val op = if (operatorName.isNotEmpty()) operatorName else operator
            if (op.isNotEmpty()) add("opérateur : $op")
        }.joinToString(" · ")

        val title = when (mode) {
            "block" -> "⛔ Appel bloqué : $number"
            "silence" -> "🔇 Appel silencié : $number"
            else -> "⚠️ Appel suspect : $number"
        }
        val reasonText = reason.ifEmpty { "présent dans les listes de spam" }

        // Mode Alerter : l'appel sonne → on affiche l'écran plein écran
        // (façon Truecaller) par-dessus l'appel entrant, via full-screen intent.
        if (mode == "alert") {
            showFullScreenAlert(number, reasonText, canReport = count == 0)
        } else {
            notify(
                number.hashCode(),
                channel(CHANNEL_ALERT, "Alertes spam", NotificationManager.IMPORTANCE_HIGH),
                title,
                reasonText,
                addReportAction = count == 0,
                number = number,
            )
        }
    }

    private fun showFullScreenAlert(number: String, reason: String, canReport: Boolean) {
        val full = Intent(this, SpamAlertActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            .putExtra(SpamAlertActivity.EXTRA_NUMBER, number)
            .putExtra(SpamAlertActivity.EXTRA_REASON, reason)
            .putExtra(SpamAlertActivity.EXTRA_CAN_REPORT, canReport)
        val pending = PendingIntent.getActivity(
            this, number.hashCode(), full,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val chan = channel(CHANNEL_ALERT, "Alertes spam", NotificationManager.IMPORTANCE_HIGH)
        val notif = Notification.Builder(this, chan)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("⚠️ Appel suspect : $number")
            .setContentText(reason)
            .setStyle(Notification.BigTextStyle().bigText(reason))
            .setCategory(Notification.CATEGORY_CALL)
            .setFullScreenIntent(pending, true)
            .setAutoCancel(true)
            .build()
        getSystemService(NotificationManager::class.java).notify(number.hashCode(), notif)
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
