package dev.micferna.antispam_app

import android.content.Context
import org.json.JSONObject
import java.io.File

/**
 * Journal local partagé (appels + SMS), une ligne JSON par événement,
 * gardé à 200 entrées. Lu par l'app via le MethodChannel (getHistory).
 */
object History {
    const val FILE = "call_history.jsonl"

    @Synchronized
    fun log(
        ctx: Context,
        kind: String,
        number: String,
        verdict: String,
        action: String,
        operator: String,
    ) {
        try {
            val entry = JSONObject()
                .put("kind", kind)
                .put("number", number)
                .put("verdict", verdict)
                .put("action", action)
                .put("operator", operator)
                .put("ts", System.currentTimeMillis())
            val file = File(ctx.filesDir, FILE)
            val lines = if (file.exists()) file.readLines().toMutableList() else mutableListOf()
            lines.add(entry.toString())
            val trimmed = if (lines.size > 200) lines.subList(lines.size - 200, lines.size) else lines
            file.writeText(trimmed.joinToString("\n"))
        } catch (_: Exception) {
            // best-effort : ne jamais faire échouer le screening.
        }
    }
}
