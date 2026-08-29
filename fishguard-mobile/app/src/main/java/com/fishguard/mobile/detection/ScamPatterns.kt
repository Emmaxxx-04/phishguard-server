package com.fishguard.mobile.detection

/**
 * Motifs de détection pour les arnaques par SMS/WhatsApp courantes en contexte
 * ouest-africain : usurpation d'identité, "avance de frais" (promesse de remboursement
 * multiplié), fausse loterie/mobile money, urgence artificielle, liens raccourcis.
 *
 * Chaque motif porte un poids ajouté au score de risque (0-100).
 * Les regex sont volontairement tolérantes aux fautes/accents pour le français parlé.
 */
object ScamPatterns {

    data class Pattern(val category: String, val regex: Regex, val weight: Int, val explanation: String)

    // --- 1. Usurpation d'identité : "je m'appelle X", "c'est moi X", nouveau numéro ---
    val impersonation = listOf(
        Pattern(
            "Usurpation d'identité",
            Regex("""(je\s+m['’]?appelle|c['’]est\s+moi|ici)\s+[A-ZÉÈÀ][a-zéèàïô]+\s+[A-ZÉÈÀ][a-zéèàïô]+""", RegexOption.IGNORE_CASE),
            25,
            "Le message se présente avec un nom complet, typique d'un contact qui se fait passer pour une personne connue de la victime."
        ),
        Pattern(
            "Changement de numéro suspect",
            Regex("""(nouveau\s+num[eé]ro|j['’]ai\s+chang[eé]\s+de\s+num[eé]ro|mon\s+ancien\s+num[eé]ro)""", RegexOption.IGNORE_CASE),
            20,
            "Prétexte classique pour justifier qu'un numéro inconnu écrit \"au nom\" d'un proche."
        )
    )

    // --- 2. Demande d'argent avec promesse de remboursement multiplié (avance de frais) ---
    val advanceFee = listOf(
        Pattern(
            "Promesse de remboursement multiplié",
            Regex("""(je\s+te\s+(renverr?ai|rembourse(rai)?)|tu\s+(recevras|auras))\s+(le\s+)?(double|triple|quadruple)""", RegexOption.IGNORE_CASE),
            35,
            "Promet de rendre 2x, 3x ou plus la somme envoyée : signature classique d'une arnaque à l'avance de frais."
        ),
        Pattern(
            "Demande de transfert d'argent",
            Regex("""(envoie[zr]?[- ]?moi|j['’]ai\s+besoin\s+que\s+tu\s+m['’]envoies?|peux[- ]?tu\s+m['’]envoyer|transf[eè]re[zr]?[- ]?moi)\s*(la\s+somme\s+de\s+)?\d""", RegexOption.IGNORE_CASE),
            30,
            "Demande explicite et directe d'un montant d'argent, souvent combinée à l'urgence."
        ),
        Pattern(
            "Montant + devise ouest-africaine",
            Regex("""\d{2,7}\s*(fcfa|f\s?cfa|xof|francs?)""", RegexOption.IGNORE_CASE),
            10,
            "Mention d'un montant précis en FCFA, cohérent avec les arnaques ciblant la sous-région."
        ),
        Pattern(
            "Référence à Mobile Money",
            Regex("""(mobile\s?money|orange\s?money|moov\s?money|wave|momo\b|flooz)""", RegexOption.IGNORE_CASE),
            8,
            "Référence à un service de mobile money, canal privilégié pour ces arnaques (transfert instantané, difficile à tracer)."
        )
    )

    // --- 3. Urgence artificielle / pression émotionnelle ---
    val urgency = listOf(
        Pattern(
            "Urgence temporelle",
            Regex("""(dans\s+(les?\s+)?\d+\s*(h|heures?|min|minutes?)|avant\s+ce\s+soir|tr[eè]s\s+urgent|c['’]est\s+urgent|imm[eé]diatement|maintenant\s+m[eê]me)""", RegexOption.IGNORE_CASE),
            20,
            "Crée une pression temporelle pour empêcher la victime de réfléchir ou de vérifier."
        ),
        Pattern(
            "Situation de détresse fabriquée",
            Regex("""(hopital|h[oô]pital|accident|urgence\s+m[eé]dicale|bloqu[eé]e?\s+(au|à)|j['’]ai\s+perdu\s+mon\s+t[eé]l[eé]phone)""", RegexOption.IGNORE_CASE),
            15,
            "Invente une situation de détresse (accident, hôpital, blocage) pour justifier une demande d'argent urgente."
        )
    )

    // --- 4. Liens suspects ---
    val links = listOf(
        Pattern(
            "Raccourcisseur de lien",
            Regex("""(bit\.ly|tinyurl|t\.co|cutt\.ly|is\.gd|rebrand\.ly|shorturl)""", RegexOption.IGNORE_CASE),
            25,
            "Lien raccourci : masque la véritable destination, très utilisé en phishing pour cacher un domaine frauduleux."
        ),
        Pattern(
            "URL avec adresse IP brute",
            Regex("""https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"""),
            30,
            "Lien pointant directement vers une adresse IP plutôt qu'un nom de domaine : quasiment jamais légitime."
        ),
        Pattern(
            "Faux domaine imitant une marque connue",
            Regex("""(orange|moov|mtn|wave|whatsapp|facebook|paypal)[-.](com|net|info|xyz|verify|secure)""", RegexOption.IGNORE_CASE),
            30,
            "Domaine qui imite le nom d'une marque connue avec un suffixe suspect, typique des pages de phishing."
        ),
        Pattern(
            "Appel à cliquer / vérifier un compte",
            Regex("""(cliquez?\s+ici|v[eé]rifiez?\s+votre\s+compte|confirmez?\s+vos?\s+identifiants?|mettre\s+[aà]\s+jour\s+votre\s+compte)""", RegexOption.IGNORE_CASE),
            18,
            "Incite à cliquer ou à ressaisir des identifiants, mécanisme central du phishing d'identifiants."
        )
    )

    // --- 5. Fausse loterie / gain / cadeau ---
    val fakeReward = listOf(
        Pattern(
            "Gain ou loterie non sollicités",
            Regex("""(vous\s+avez\s+gagn[eé]|f[eé]licitations?.{0,20}(gagn|s[eé]lectionn)|tirage\s+au\s+sort|loterie)""", RegexOption.IGNORE_CASE),
            22,
            "Annonce d'un gain que la victime n'a jamais sollicité, classique amorce d'arnaque \"vous avez gagné\"."
        )
    )

    // --- 6. Vol de code OTP / vérification ---
    val otpTheft = listOf(
        Pattern(
            "Demande de code de vérification",
            Regex("""(donn(e|ez)[- ]?moi|envoie[zr]?[- ]?moi|quel\s+est|dicte[- ]?moi)\s+(le\s+)?(code|otp)\b""", RegexOption.IGNORE_CASE),
            32,
            "Demande explicite du code de vérification reçu par SMS : c'est précisément ce mécanisme qui permet de détourner un compte Mobile Money ou WhatsApp."
        ),
        Pattern(
            "Référence à un code reçu",
            Regex("""(code\s+(que\s+)?(tu|vous)\s+(as|avez)\s+re[cç]u|le\s+code\s+[aà]\s+6\s+chiffres)""", RegexOption.IGNORE_CASE),
            20,
            "Fait référence à un code de vérification que la victime vient de recevoir, signe d'une tentative de contournement d'authentification."
        )
    )

    // --- 7. Demande de coordonnées bancaires / carte ---
    val bankInfoRequest = listOf(
        Pattern(
            "Demande de coordonnées bancaires",
            Regex("""(num[eé]ro\s+de\s+carte|code\s+cvv|date\s+d['’]expiration|code\s+secret\s+(de\s+la\s+)?carte|num[eé]ro\s+de\s+compte)""", RegexOption.IGNORE_CASE),
            30,
            "Demande des informations bancaires sensibles : aucune institution légitime ne les demande par SMS ou WhatsApp."
        ),
        Pattern(
            "Faux support / service client",
            Regex("""(service\s+client|support\s+technique|votre\s+compte\s+(a\s+[eé]t[eé]\s+)?(suspendu|bloqu[eé]|limit[eé]))""", RegexOption.IGNORE_CASE),
            18,
            "Se présente comme un service client officiel pour justifier une demande d'informations sensibles."
        )
    )

    // --- 8. Menace / extorsion ---
    val extortion = listOf(
        Pattern(
            "Menace ou chantage",
            Regex("""(sinon\s+(je|nous)|si\s+tu\s+ne\s+(paies?|envoies?)\s+pas|je\s+vais\s+(publier|diffuser|signaler)|des\s+cons[eé]quences)""", RegexOption.IGNORE_CASE),
            28,
            "Menace explicite en cas de non-paiement ou de non-réponse : schéma classique d'extorsion/chantage."
        )
    )

    // --- 9. Offre d'emploi ou opportunité trop belle pour être vraie ---
    val tooGoodOffer = listOf(
        Pattern(
            "Offre d'emploi non sollicitée",
            Regex("""(offre\s+d['’]emploi|recrutement\s+urgent|travail\s+[aà]\s+domicile|gagnez?\s+\d+.{0,15}par\s+jour)""", RegexOption.IGNORE_CASE),
            18,
            "Propose une opportunité de gain rapide non sollicitée, schéma fréquent des arnaques à l'emploi fictif."
        )
    )

    // --- 10. Heuristiques stylistiques (indicateurs faibles, mais utiles en combinaison) ---
    val stylistic = listOf(
        Pattern(
            "Ponctuation d'alerte excessive",
            Regex("""[!?]{3,}"""),
            6,
            "Usage de ponctuation exagérée, technique courante pour créer un sentiment d'urgence ou de gravité."
        )
    )

    val all: List<Pattern> = impersonation + advanceFee + urgency + links + fakeReward +
        otpTheft + bankInfoRequest + extortion + tooGoodOffer + stylistic
}
