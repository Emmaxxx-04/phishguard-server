package com.fishguard.mobile.ui.learn

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material.icons.filled.Report
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.ui.graphics.vector.ImageVector

data class LearnArticle(
    val icon: ImageVector,
    val title: String,
    val summary: String,
    val doThis: List<String>,
    val avoidThis: List<String>
)

/**
 * Contenu de sensibilisation, taillé pour le contexte ouest-africain
 * (Mobile Money, WhatsApp, SMS bancaires). Volontairement statique et
 * embarqué dans l'app : disponible même sans connexion.
 */
object LearnContent {

    val articles = listOf(
        LearnArticle(
            icon = Icons.Filled.Call,
            title = "Arnaques par appel téléphonique",
            summary = "FishGuard ne peut pas écouter tes appels par défaut — voici comment te protéger, et ce que propose le mode protection en direct.",
            doThis = listOf(
                "Raccroche et rappelle toi-même le numéro officiel (banque, opérateur) si quelqu'un se présente comme tel et te demande une action urgente.",
                "Signale le numéro dans FishGuard (Réglages > Protection des appels) dès que tu identifies un appel frauduleux.",
                "Si tu actives la protection en direct, mets bien l'appel en haut-parleur et informe ton interlocuteur que l'appel est analysé.",
                "Après un appel qui te semble louche, utilise aussi \"Tester un message\" (source \"Appel\") pour une analyse a posteriori."
            ),
            avoidThis = listOf(
                "Ne communique jamais un code OTP, un mot de passe ou un code Mobile Money par téléphone — aucun service légitime ne le demande ainsi.",
                "Ne te laisse pas presser par l'urgence (\"il faut agir maintenant sinon...\") : c'est le levier numéro un des arnaqueurs par téléphone.",
                "Ne rappelle jamais un numéro inconnu qui t'a appelé une seule fois puis raccroché (technique \"Wangiri\" pour te faire rappeler un numéro surtaxé)."
            )
        ),
        LearnArticle(
            icon = Icons.Filled.Search,
            title = "Reconnaître un message d'hameçonnage",
            summary = "Les signes qui doivent te mettre la puce à l'oreille, avant même d'utiliser FishGuard.",
            doThis = listOf(
                "Vérifie l'identité de l'expéditeur : un numéro inconnu qui prétend être un proche est un signal fort.",
                "Prends le temps de réfléchir, même si le message insiste sur l'urgence — c'est justement le but recherché.",
                "Appelle directement la personne ou l'organisme concerné, via un numéro que tu connais déjà, pour vérifier.",
                "Regarde l'adresse exacte des liens avant de cliquer (survole ou maintiens appuyé pour la prévisualiser)."
            ),
            avoidThis = listOf(
                "Ne réponds jamais dans la précipitation à une demande d'argent, même venant d'un \"proche\".",
                "Ne clique pas sur un lien raccourci (bit.ly, tinyurl...) reçu sans contexte.",
                "Ne crois pas un message uniquement parce qu'il connaît ton nom ou ton numéro."
            )
        ),
        LearnArticle(
            icon = Icons.Filled.PhoneAndroid,
            title = "Mobile Money : Orange Money, Wave, Moov, MTN MoMo",
            summary = "Les arnaques les plus fréquentes ciblent directement ton compte mobile money.",
            doThis = listOf(
                "Vérifie toujours le montant ET le numéro affiché sur l'écran de confirmation avant de valider un envoi.",
                "En cas de doute sur un \"code marchand\" ou un \"agent\", appelle le numéro officiel de l'opérateur.",
                "Compose toi-même le code USSD (#144#, #150# etc.) plutôt que de suivre un lien envoyé par SMS."
            ),
            avoidThis = listOf(
                "Ne communique JAMAIS ton code secret Mobile Money à qui que ce soit, y compris à un \"agent\" ou au \"service client\".",
                "Ne rappelle pas un numéro inconnu qui te dit avoir \"envoyé de l'argent par erreur\" — c'est une arnaque très répandue.",
                "Ne fais jamais de retrait ou de transfert sous pression téléphonique en direct."
            )
        ),
        LearnArticle(
            icon = Icons.Filled.Lock,
            title = "Sécuriser son compte WhatsApp",
            summary = "WhatsApp est une cible privilégiée : usurpation de compte, faux support, faux concours.",
            doThis = listOf(
                "Active la vérification en deux étapes (Réglages > Compte > Confirmation en deux étapes) et choisis un code que toi seul connais.",
                "Vérifie l'identité derrière un nouveau numéro avant de continuer une conversation sensible (appel vidéo par exemple).",
                "Signale et bloque les comptes qui se font passer pour des proches ou des services officiels."
            ),
            avoidThis = listOf(
                "Ne transmets jamais le code à 6 chiffres reçu par SMS, même si on te dit que c'est pour \"confirmer ton compte\" : ce code permet de voler ton compte WhatsApp.",
                "Ne fais pas confiance à un \"nouveau numéro\" d'un proche sans vérification par un autre canal.",
                "Ne participe pas à des \"concours\" ou \"cadeaux\" relayés en chaîne demandant tes informations personnelles."
            )
        ),
        LearnArticle(
            icon = Icons.Filled.Shield,
            title = "L'ingénierie sociale : comment on te manipule",
            summary = "Les arnaqueurs s'appuient sur des ressorts psychologiques précis, pas sur la technique.",
            doThis = listOf(
                "Repère les 3 leviers classiques : l'urgence (\"vite, avant ce soir\"), l'autorité (\"je suis de la banque\"), et l'émotion (\"j'ai un accident, aide-moi\").",
                "Plus la pression est forte, plus la vigilance doit augmenter — c'est un signal, pas une coïncidence.",
                "Parle-en à quelqu'un avant d'agir si un message te met mal à l'aise : un regard extérieur détecte souvent l'arnaque immédiatement."
            ),
            avoidThis = listOf(
                "Ne laisse jamais une situation \"urgente\" court-circuiter ta vérification habituelle.",
                "Ne te sens pas obligé de répondre immédiatement à un message qui exige une réponse instantanée."
            )
        ),
        LearnArticle(
            icon = Icons.Filled.Wifi,
            title = "Bonnes pratiques générales",
            summary = "Des réflexes simples qui réduisent la majorité des risques au quotidien.",
            doThis = listOf(
                "Utilise un mot de passe différent pour chaque service important, si possible avec un gestionnaire de mots de passe.",
                "Maintiens ton téléphone et tes applications à jour : les mises à jour corrigent des failles de sécurité connues.",
                "Active le verrouillage d'écran (code, empreinte) pour limiter les dégâts en cas de perte ou de vol.",
                "Fais des sauvegardes régulières de tes contacts et documents importants."
            ),
            avoidThis = listOf(
                "Évite de te connecter à des Wi-Fi publics non protégés pour des opérations sensibles (banque, mobile money).",
                "N'installe pas d'application en dehors du Play Store, surtout si elle promet un gain d'argent facile."
            )
        ),
        LearnArticle(
            icon = Icons.Filled.Report,
            title = "Que faire si tu as été victime ?",
            summary = "Agir vite limite les dégâts — voici l'ordre des priorités.",
            doThis = listOf(
                "Change immédiatement le code/mot de passe du compte concerné (Mobile Money, WhatsApp, banque).",
                "Contacte le service client officiel de l'opérateur ou de la banque pour signaler la fraude et bloquer les transactions en cours.",
                "Si un montant a été envoyé par erreur ou par arnaque, demande immédiatement un ticket/reçu de réclamation — beaucoup d'opérateurs peuvent bloquer les fonds s'ils sont contactés rapidement.",
                "Informe tes proches si ton compte WhatsApp ou un compte social a été compromis, pour qu'ils ne soient pas piégés à leur tour.",
                "Conserve une capture d'écran du message frauduleux (utile pour un signalement ou une plainte)."
            ),
            avoidThis = listOf(
                "N'attends pas \"pour voir\" — chaque minute compte pour bloquer un transfert frauduleux.",
                "Ne culpabilise pas : les techniques utilisées sont conçues par des professionnels de la manipulation, ça peut arriver à n'importe qui."
            )
        )
    )
}
