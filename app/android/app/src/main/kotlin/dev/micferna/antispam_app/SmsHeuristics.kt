package dev.micferna.antispam_app

/**
 * Heuristiques anti-smishing exécutées SUR LE TÉLÉPHONE.
 *
 * Réplique de `backend/src/sms.rs` (même listes, mêmes seuils), sur le même
 * principe que les préfixes ARCEP dupliqués dans SpamScreeningService : le
 * contenu d'un SMS est la donnée la plus sensible que l'app voit passer —
 * codes à usage unique, messages privés, informations bancaires. L'analyse
 * étant purement déterministe (mots-clés, forme des liens), rien n'oblige à
 * l'envoyer au serveur : il ne reçoit plus que le numéro de l'expéditeur,
 * dont il est seul à connaître la réputation.
 *
 * Effet de bord utile : la détection continue de fonctionner serveur
 * injoignable.
 *
 * En cas de divergence avec le backend, `sms.rs` fait foi.
 */
object SmsHeuristics {

    private val SHORTENERS = listOf(
        "bit.ly", "tinyurl.com", "cutt.ly", "rb.gy", "is.gd", "t.co",
        "ow.ly", "buff.ly", "shorturl.at", "urlz.fr", "lc.cx", "tiny.cc",
    )

    /** (marque citée dans le texte, domaine officiel légitime) */
    private val BRAND_DOMAINS = listOf(
        "laposte" to "laposte.fr",
        "colissimo" to "laposte.fr",
        "chronopost" to "chronopost.fr",
        "ameli" to "ameli.fr",
        "impots" to "impots.gouv.fr",
        "cpf" to "moncompteformation.gouv.fr",
        "netflix" to "netflix.com",
        "paypal" to "paypal.com",
        "vinted" to "vinted.fr",
    )

    private val SCAM_KEYWORDS = listOf(
        "colis", "livraison", "suivi de votre", "frais de douane", "frais de port",
        "compte a ete", "compte bloque", "compte suspendu", "suspendu",
        "verifiez vos informations", "mettre a jour vos", "cliquez", "cliquez ici",
        "urgent", "derniere relance", "dernier avis", "cpf", "compte formation",
        "remboursement", "vous avez gagne", "cadeau", "carte vitale", "carte grise",
        "amende", "penalite", "identifiant", "mot de passe", "code de securite",
        "confirmez",
    )

    data class Analysis(val suspicious: Boolean, val signals: List<String>)

    private fun stripAccents(s: String): String = buildString(s.length) {
        for (c in s) append(
            when (c) {
                'à', 'â', 'ä' -> 'a'
                'é', 'è', 'ê', 'ë' -> 'e'
                'î', 'ï' -> 'i'
                'ô', 'ö' -> 'o'
                'ù', 'û', 'ü' -> 'u'
                'ç' -> 'c'
                else -> c
            }
        )
    }.lowercase()

    /** Extraction grossière des URLs (http/https/www), comme côté backend. */
    private fun extractUrls(text: String): List<String> =
        text.lowercase().split(Regex("\\s+")).filter {
            it.startsWith("http://") || it.startsWith("https://") || it.startsWith("www.")
        }.map { it.trimEnd('.', ',', ')', ']') }

    fun analyze(text: String): Analysis {
        val norm = stripAccents(text)
        val urls = extractUrls(text)
        val hasUrl = urls.isNotEmpty()
        val signals = mutableListOf<String>()
        if (hasUrl) signals += "contient un lien"

        val usesShortener = urls.any { u -> SHORTENERS.any { u.contains(it) } }
        if (usesShortener) signals += "lien raccourci (destination masquée)"

        val brandSpoof = hasUrl && BRAND_DOMAINS.any { (brand, domain) ->
            norm.contains(brand) && urls.none { it.contains(domain) }
        }
        if (brandSpoof) signals += "marque connue + lien non officiel"

        val hits = SCAM_KEYWORDS.count { norm.contains(it) }

        // Décision conservatrice, identique à `is_suspicious_sms` : on préfère
        // rater un smishing que crier au loup sur un code OTP légitime.
        val suspicious = brandSpoof ||
            (usesShortener && hits >= 1) ||
            (hasUrl && hits >= 2) ||
            hits >= 3
        return Analysis(suspicious, signals)
    }
}
