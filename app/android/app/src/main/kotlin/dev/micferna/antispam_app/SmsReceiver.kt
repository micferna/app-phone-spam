package dev.micferna.antispam_app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Telephony
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import kotlin.concurrent.thread

/**
 * Reçoit les SMS entrants (sans être l'app SMS par défaut) et les vérifie
 * auprès du serveur (/api/check-sms) : expéditeur connu + heuristiques
 * anti-smishing. Si suspect → notification d'alerte. On ne peut pas
 * bloquer/supprimer le SMS (réservé à l'app SMS par défaut).
 */
class SmsReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return

        val prefs = context.getSharedPreferences("FlutterSharedPreferences", Context.MODE_PRIVATE)
        if (!prefs.getBoolean("flutter.sms_filter", false)) return
        val serverUrl = prefs.getString("flutter.server_url", null) ?: return
        val apiKey = prefs.getString("flutter.api_key", null) ?: return

        // Reconstitue l'expéditeur et le texte (SMS multi-parties concaténés).
        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent) ?: return
        if (messages.isEmpty()) return
        val sender = messages[0].displayOriginatingAddress ?: return
        val body = messages.joinToString("") { it.displayMessageBody ?: "" }

        val pending = goAsync()
        thread {
            try {
                val conn = URL("$serverUrl/api/check-sms").openConnection() as HttpURLConnection
                conn.requestMethod = "POST"
                conn.doOutput = true
                conn.setRequestProperty("X-Api-Key", apiKey)
                conn.setRequestProperty("Content-Type", "application/json")
                conn.connectTimeout = 4000
                conn.readTimeout = 4000
                conn.outputStream.write(
                    JSONObject().put("sender", sender).put("text", body).toString().toByteArray()
                )
                val json = JSONObject(conn.inputStream.bufferedReader().readText())
                conn.disconnect()

                if (json.optBoolean("suspicious")) {
                    val reasons = json.optJSONArray("reasons")
                    val reasonText = buildString {
                        if (reasons != null) {
                            for (i in 0 until reasons.length()) {
                                if (i > 0) append(" · ")
                                append(reasons.optString(i))
                            }
                        }
                    }.ifEmpty { "signaux d'arnaque détectés" }
                    notifySms(context, sender, body, reasonText, json.optBoolean("canReport"))
                    History.log(context, "sms", sender, "suspect", "SMS suspect", "")
                }
            } catch (_: Exception) {
                // Serveur injoignable : on ne dérange pas.
            } finally {
                pending.finish()
            }
        }
    }

    private fun notifySms(
        context: Context,
        sender: String,
        body: String,
        reason: String,
        canReport: Boolean,
    ) {
        val nm = context.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_SMS, "SMS suspects", NotificationManager.IMPORTANCE_HIGH)
        )
        val id = sender.hashCode()
        val builder = Notification.Builder(context, CHANNEL_SMS)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("⚠️ SMS suspect de $sender")
            .setContentText(reason)
            .setStyle(Notification.BigTextStyle().bigText(reason))
            .setAutoCancel(true)

        if (canReport) {
            val intent = Intent(context, ReportReceiver::class.java)
                .setAction(ReportReceiver.ACTION_REPORT)
                .putExtra(ReportReceiver.EXTRA_NUMBER, sender)
                .putExtra(ReportReceiver.EXTRA_NOTIFICATION_ID, id)
            val pi = PendingIntent.getBroadcast(
                context, id, intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            builder.addAction(
                Notification.Action.Builder(null, "Signaler l'expéditeur", pi).build()
            )
        }

        // Aide au signalement officiel : ouvre l'app SMS pré-remplie vers le
        // 33700 (plateforme nationale anti-spam) avec le message frauduleux.
        val forward = Intent(Intent.ACTION_SENDTO, Uri.parse("smsto:33700"))
            .putExtra("sms_body", body)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (forward.resolveActivity(context.packageManager) != null) {
            val fpi = PendingIntent.getActivity(
                context, id + 1, forward,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            builder.addAction(
                Notification.Action.Builder(null, "Transférer au 33700", fpi).build()
            )
        }
        nm.notify("sms".hashCode() + sender.hashCode(), builder.build())
    }

    companion object {
        const val CHANNEL_SMS = "sms_alert"
    }
}
