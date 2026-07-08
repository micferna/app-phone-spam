package dev.micferna.antispam_app

import android.app.Activity
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.telecom.TelecomManager
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

/**
 * Écran plein écran affiché par-dessus l'appel entrant quand un numéro
 * suspect appelle (mode « Alerter »), façon Truecaller : info riche +
 * actions, sans être l'application téléphone par défaut. Lancé via un
 * full-screen intent depuis SpamScreeningService.
 */
class SpamAlertActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // S'afficher même écran verrouillé, et réveiller l'écran.
        if (Build.VERSION.SDK_INT >= 27) {
            setShowWhenLocked(true)
            setTurnScreenOn(true)
        } else {
            @Suppress("DEPRECATION")
            window.addFlags(
                WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or
                    WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON or
                    WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON
            )
        }

        val number = intent.getStringExtra(EXTRA_NUMBER) ?: "?"
        val reason = intent.getStringExtra(EXTRA_REASON) ?: "présent dans les listes de spam"
        val canReport = intent.getBooleanExtra(EXTRA_CAN_REPORT, false)

        val pad = dp(24)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setBackgroundColor(Color.parseColor("#B3160B"))
            setPadding(pad, pad, pad, pad)
        }

        root.addView(text("⚠️", 64f, Color.WHITE, bold = true))
        root.addView(text("Appel suspect", 26f, Color.WHITE, bold = true, topDp = 8))
        root.addView(text(number, 30f, Color.WHITE, bold = true, topDp = 16))
        root.addView(text(reason, 17f, Color.parseColor("#FFE0DC"), topDp = 16))

        if (canReport) {
            root.addView(
                actionButton("Signaler comme spam", Color.WHITE, Color.parseColor("#B3160B")) {
                    reportNumber(number)
                    finish()
                }
            )
        }
        root.addView(
            actionButton("Raccrocher", Color.parseColor("#7A0A03"), Color.WHITE) {
                endCall()
                finish()
            }
        )
        root.addView(
            actionButton("Fermer", Color.TRANSPARENT, Color.WHITE) { finish() }
        )

        setContentView(root)
    }

    private fun reportNumber(number: String) {
        val i = android.content.Intent(this, ReportReceiver::class.java)
            .setAction(ReportReceiver.ACTION_REPORT)
            .putExtra(ReportReceiver.EXTRA_NUMBER, number)
            .putExtra(ReportReceiver.EXTRA_NOTIFICATION_ID, number.hashCode())
        sendBroadcast(i)
    }

    private fun endCall() {
        try {
            val tm = getSystemService(TelecomManager::class.java)
            if (Build.VERSION.SDK_INT >= 28 &&
                checkSelfPermission(android.Manifest.permission.ANSWER_PHONE_CALLS)
                == android.content.pm.PackageManager.PERMISSION_GRANTED
            ) {
                @Suppress("DEPRECATION")
                tm.endCall()
            }
        } catch (_: Exception) {
            // Raccrochage indisponible : l'utilisateur rejette via son app téléphone.
        }
    }

    // --- helpers UI ---
    private fun dp(v: Int) =
        TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v.toFloat(), resources.displayMetrics).toInt()

    private fun text(s: String, size: Float, color: Int, bold: Boolean = false, topDp: Int = 0) =
        TextView(this).apply {
            text = s
            textSize = size
            setTextColor(color)
            gravity = Gravity.CENTER
            if (bold) setTypeface(typeface, android.graphics.Typeface.BOLD)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = dp(topDp) }
        }

    private fun actionButton(label: String, bg: Int, fg: Int, onClick: () -> Unit) =
        Button(this).apply {
            text = label
            setTextColor(fg)
            setBackgroundColor(bg)
            isAllCaps = false
            textSize = 17f
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = dp(12) }
            setOnClickListener { onClick() }
            visibility = View.VISIBLE
        }

    companion object {
        const val EXTRA_NUMBER = "number"
        const val EXTRA_REASON = "reason"
        const val EXTRA_CAN_REPORT = "can_report"
    }
}
