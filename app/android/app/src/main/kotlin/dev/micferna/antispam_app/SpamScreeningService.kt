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
import android.telecom.TelecomManager
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
        val chosenMode = prefs.getString("flutter.screening_mode", "alert") ?: "alert"
        val skipContacts = prefs.getBoolean("flutter.skip_contacts", true)
        // « Ne pas déranger la nuit » : les appels suspects sont silenciés la
        // nuit même en mode Alerter.
        val mode = if (chosenMode == "alert" && nightSilenceActive(prefs)) "silence" else chosenMode

        // Numéro masqué / anonyme : décision purement locale (aucun numéro à
        // interroger). Réglage `hidden_mode` : ring (défaut) | silence | block.
        val presentation = callDetails.handlePresentation
        val hidden = number.isNullOrBlank() ||
            presentation == TelecomManager.PRESENTATION_RESTRICTED ||
            presentation == TelecomManager.PRESENTATION_UNKNOWN
        if (hidden) {
            val hiddenMode = prefs.getString("flutter.hidden_mode", "ring") ?: "ring"
            val response = when (hiddenMode) {
                "block" -> CallResponse.Builder().setDisallowCall(true).setRejectCall(true).build()
                "silence" -> CallResponse.Builder().setSilenceCall(true).build()
                else -> CallResponse.Builder().build()
            }
            respondToCall(callDetails, response)
            if (hiddenMode != "ring") {
                val action = if (hiddenMode == "block") "bloqué" else "silencié"
                logHistory("Masqué", "masqué", action, "")
                notifyHidden(hiddenMode)
            }
            return
        }

        if (number == null || serverUrl == null || apiKey == null) {
            respondToCall(callDetails, CallResponse.Builder().build())
            return
        }

        // Exemption des contacts + whitelist manuelle : jamais filtrés.
        if ((skipContacts && isInContacts(number)) || isWhitelisted(prefs, number)) {
            respondToCall(callDetails, CallResponse.Builder().build())
            logHistory(number, "contact", "laissé sonner", "")
            return
        }

        // Détection locale des plages ARCEP de démarchage : fiable même serveur
        // injoignable / réseau lent (ces numéros 0270…, 0568…, 0948… SONT du
        // démarchage par définition, pas besoin du serveur pour le savoir).
        val arcepLocal = isArcepDemarchage(number)
        // Règles par catégorie (VoIP 09 / international / surtaxé 08) : décision
        // locale selon les interrupteurs de réglages. Non-null = catégorie
        // filtrée par l'utilisateur → traitée comme suspecte selon le mode.
        val categoryLabel = blockedCategoryLabel(number, prefs)

        if (mode == "alert") {
            // Ne jamais retarder la sonnerie : on laisse passer tout de
            // suite, la notification arrive pendant que ça sonne.
            respondToCall(callDetails, CallResponse.Builder().build())
            thread {
                val json = lookup(serverUrl, apiKey, number)
                when {
                    json != null && json.optBoolean("suspicious") -> {
                        notifySuspicious(json, mode)
                        logHistory(number, "suspect", "alerte", operatorLabel(json))
                    }
                    // Serveur muet mais plage ARCEP connue localement.
                    json == null && arcepLocal -> {
                        notifySuspicious(arcepJson(number), mode)
                        logHistory(number, "suspect", "alerte (ARCEP local)", "")
                    }
                    // Règle de catégorie de l'utilisateur (VoIP/international/surtaxé).
                    categoryLabel != null -> {
                        notifySuspicious(localJson(number, categoryLabel), mode)
                        logHistory(number, "suspect", "alerte (catégorie)", "")
                    }
                    else -> {
                        notifyUnknown(json?.optString("number", number) ?: number)
                        logHistory(number, "inconnu", "laissé sonner", "")
                    }
                }
            }
            return
        }

        // Modes silence / block : la réponse au système attend le verdict.
        thread {
            val json = lookup(serverUrl, apiKey, number)
            // Suspect si : plage ARCEP (local, fiable hors-ligne) OU verdict
            // serveur OU cache hors-ligne. Garantit le blocage des 0270/0568/…
            // même si le backend est injoignable au moment de l'appel.
            val suspicious = json?.optBoolean("suspicious") == true ||
                arcepLocal ||
                categoryLabel != null ||
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
            when {
                json != null && json.optBoolean("suspicious") -> notifySuspicious(json, mode)
                suspicious && arcepLocal -> notifySuspicious(arcepJson(number), mode)
                suspicious && categoryLabel != null ->
                    notifySuspicious(localJson(number, categoryLabel), mode)
                !suspicious -> notifyUnknown(json?.optString("number", number) ?: number)
            }
            logHistory(number, verdict, action, json?.let { operatorLabel(it) } ?: "")
            // Auto-signalement : on ne remonte au groupe QUE des signaux objectifs
            // (plage ARCEP ou verdict serveur), encore inconnus (reportCount 0).
            // Un blocage « catégorie perso » (VoIP/international/surtaxé) ou issu
            // du cache n'est PAS remonté, pour ne pas polluer le groupe avec des
            // préférences individuelles. Désactivable (flutter.auto_report).
            val known = json?.optInt("reportCount", 0) ?: 0
            val objectiveSpam = arcepLocal || json?.optBoolean("suspicious") == true
            if (objectiveSpam && known == 0 && prefs.getBoolean("flutter.auto_report", true)) {
                autoReport(serverUrl, apiKey, number, if (arcepLocal) "demarchage" else "auto")
            }
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

    // --- Whitelist manuelle (préférence flutter.whitelist = tableau JSON) ---
    private fun isWhitelisted(prefs: android.content.SharedPreferences, number: String): Boolean {
        val raw = prefs.getString("flutter.whitelist", null) ?: return false
        return try {
            val arr = JSONArray(raw)
            (0 until arr.length()).any { arr.optString(it) == number }
        } catch (_: Exception) {
            false
        }
    }

    // --- « Ne pas déranger la nuit » : plage horaire flutter.night_start/end
    // (heures), actif si flutter.night_silence est vrai. ---
    private fun nightSilenceActive(prefs: android.content.SharedPreferences): Boolean {
        if (!prefs.getBoolean("flutter.night_silence", false)) return false
        val start = prefs.getLong("flutter.night_start", 21).toInt()
        val end = prefs.getLong("flutter.night_end", 8).toInt()
        val hour = java.util.Calendar.getInstance().get(java.util.Calendar.HOUR_OF_DAY)
        return if (start <= end) hour in start until end else hour >= start || hour < end
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

    // --- Plages ARCEP réservées au démarchage (décision 2022-1583).
    // Réplique de backend/src/normalize.rs pour un blocage 100 % hors-ligne. ---
    private val arcepPrefixes = listOf(
        "+33162", "+33163", "+33270", "+33271", "+33377", "+33378",
        "+33424", "+33425", "+33568", "+33569", "+33948", "+33949",
        "+339475", "+339476", "+339477", "+339478", "+339479",
    )

    /// Normalise vers E.164 FR (06… / 0033… / +33…) sans validation stricte :
    /// on cherche seulement à comparer un préfixe.
    private fun toE164(raw: String): String {
        var n = raw.filter { it !in " .-()\t" }
        if (n.startsWith("00")) n = "+" + n.substring(2)
        if (n.length == 10 && n.startsWith("0") && n[1] != '0') n = "+33" + n.substring(1)
        return n
    }

    private fun isArcepDemarchage(number: String): Boolean {
        val e = toE164(number)
        return arcepPrefixes.any { e.startsWith(it) }
    }

    /// JSON minimal pour notifier un blocage ARCEP décidé localement (sans
    /// réponse serveur), consommé par notifySuspicious().
    private fun arcepJson(number: String): JSONObject = JSONObject()
        .put("number", number)
        .put("arcepDemarchage", true)
        .put("suspicious", true)
        .put("reportCount", 0)

    /// JSON minimal pour notifier un blocage décidé localement avec un motif
    /// personnalisé (repris par notifySuspicious via `importedLabel`).
    private fun localJson(number: String, label: String): JSONObject = JSONObject()
        .put("number", number)
        .put("suspicious", true)
        .put("reportCount", 0)
        .put("importedLabel", label)

    /// Règles par catégorie de ligne (réglages), en local. Renvoie le motif si
    /// la catégorie du numéro est filtrée par l'utilisateur, sinon null.
    private fun blockedCategoryLabel(
        number: String,
        prefs: android.content.SharedPreferences,
    ): String? {
        val e = toE164(number)
        if (!e.startsWith("+33") && e.startsWith("+") &&
            prefs.getBoolean("flutter.block_intl", false)
        ) {
            return "Appel international — filtré selon tes réglages"
        }
        if (e.startsWith("+33")) {
            when (e.getOrNull(3)) {
                '9' -> if (prefs.getBoolean("flutter.block_voip", false)) {
                    return "Numéro VoIP / non géographique (09) — filtré"
                }
                '8' -> if (e.getOrNull(4) != '0' &&
                    prefs.getBoolean("flutter.block_premium", false)
                ) {
                    return "Numéro surtaxé (08) — filtré"
                }
            }
        }
        return null
    }

    private fun operatorLabel(json: JSONObject): String {
        val name = if (json.isNull("operatorName")) "" else json.optString("operatorName", "")
        return if (name.isNotEmpty()) name else if (json.isNull("operator")) "" else json.optString("operator", "")
    }

    private fun logHistory(number: String, verdict: String, action: String, operator: String) {
        History.log(this, "call", number, verdict, action, operator)
    }

    /// Signale au backend un numéro que l'app vient de bloquer/silencier
    /// (fire-and-forget ; tout échec réseau est ignoré). Le serveur normalise
    /// et déduplique (upsert par user+numéro).
    private fun autoReport(serverUrl: String, apiKey: String, number: String, category: String) {
        try {
            val conn = URL("$serverUrl/api/reports").openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.setRequestProperty("X-Api-Key", apiKey)
            conn.setRequestProperty("Content-Type", "application/json")
            conn.doOutput = true
            conn.connectTimeout = 3000
            conn.readTimeout = 3000
            val body = JSONObject()
                .put("number", number)
                .put("category", category)
                .put("comment", "auto : bloqué par l'app")
                .toString()
            conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            conn.inputStream.use { it.readBytes() }
            conn.disconnect()
        } catch (_: Exception) {
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

        val operatorName = if (json.isNull("operatorName")) "" else json.optString("operatorName", "")
        val operator = if (json.isNull("operator")) "" else json.optString("operator", "")
        val campaign = json.optBoolean("campaignActive")
        val score = json.optInt("suspicionScore", 0)
        val reason = buildList {
            if (campaign) add("⚡ campagne de démarchage en cours sur cette plage")
            if (count > 0) add("signalé par $count personne${if (count > 1) "s" else ""} du groupe")
            if (arcep) add("préfixe officiel de démarchage (ARCEP)")
            if (label.isNotEmpty() && !arcep) add(label)
            val op = if (operatorName.isNotEmpty()) operatorName else operator
            if (op.isNotEmpty()) add("opérateur : $op")
            if (score > 0) add("score de risque : $score/100")
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

    private fun notifyHidden(mode: String) {
        val title =
            if (mode == "block") "⛔ Appel masqué bloqué" else "🔇 Appel masqué silencié"
        val chan = channel(CHANNEL_ALERT, "Alertes spam", NotificationManager.IMPORTANCE_HIGH)
        val notif = Notification.Builder(this, chan)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle(title)
            .setContentText("Numéro masqué / anonyme filtré selon tes réglages.")
            .setAutoCancel(true)
            .build()
        getSystemService(NotificationManager::class.java).notify("hidden".hashCode(), notif)
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
