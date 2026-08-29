package com.fishguard.mobile.detection

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RuleBasedDetectorTest {

    private val detector = RuleBasedDetector()

    @Test
    fun `demande de code de verification est fortement signalee`() {
        val text = "Bonjour, je suis du service client Orange, donnez-moi le code que vous avez reçu pour débloquer votre compte"
        val result = detector.analyze("SMS", text)

        assertTrue(result.score >= 30)
        assertTrue(result.signals.any { it.category == "Demande de code de vérification" })
    }

    @Test
    fun `usurpation depuis un numero non enregistre augmente le score par rapport a un numero enregistre`() {
        val text = "c'est moi Awa Diallo, envoie-moi 5000 fcfa stp"

        val fromUnknownNumber = detector.analyze("SMS", text, sender = "+22890112233")
        val fromSavedContact = detector.analyze("SMS", text, sender = "Awa Diallo")

        assertTrue(
            "Le score depuis un numéro brut doit être supérieur (${fromUnknownNumber.score}) à celui depuis un contact enregistré (${fromSavedContact.score})",
            fromUnknownNumber.score > fromSavedContact.score
        )
        assertTrue(fromUnknownNumber.signals.any { it.category == "Numéro inconnu + usurpation" })
    }

    @Test
    fun `la sensibilite deplace le score et peut changer le niveau de risque en zone limite`() {
        val text = "Envoie-moi 5000 fcfa stp" // score de base ~40 (MEDIUM)

        val low = detector.analyze("SMS", text, sensitivity = Sensitivity.LOW)
        val normal = detector.analyze("SMS", text, sensitivity = Sensitivity.NORMAL)
        val high = detector.analyze("SMS", text, sensitivity = Sensitivity.HIGH)

        assertTrue(low.score < normal.score)
        assertTrue(high.score > normal.score)
    }

    @Test
    fun `message d usurpation avec avance de frais est detecte comme risque critique ou eleve`() {
        val text = "je m'appelle emmanuel adebayor j'ai besoin que tu m'envoie 10000 et je te renverai le triple dans 24h"
        val result = detector.analyze("WhatsApp", text)

        assertTrue(
            "Score attendu >= 55 (HIGH ou CRITICAL), obtenu ${result.score}",
            result.score >= 55
        )
        assertTrue(result.riskLevel == RiskLevel.HIGH || result.riskLevel == RiskLevel.CRITICAL)
        assertTrue(result.signals.any { it.category == "Usurpation d'identité" })
        assertTrue(result.signals.any { it.category == "Promesse de remboursement multiplié" })
        assertTrue(result.signals.any { it.category == "Urgence temporelle" })
    }

    @Test
    fun `message benin sans mots-cles n'est pas signale`() {
        val text = "Salut, on se voit toujours pour le foot samedi ? Dis-moi si ça marche pour toi."
        val result = detector.analyze("SMS", text)

        assertEquals(RiskLevel.SAFE, result.riskLevel)
        assertTrue(result.signals.isEmpty())
    }

    @Test
    fun `lien avec adresse IP brute augmente fortement le score`() {
        val text = "Votre colis est bloqué, cliquez ici pour confirmer : http://192.168.55.2/verify"
        val result = detector.analyze("SMS", text)

        assertTrue(result.score >= 30)
        assertTrue(result.signals.any { it.category == "URL avec adresse IP brute" })
    }

    @Test
    fun `fausse loterie mobile money est detectee`() {
        val text = "Félicitations, vous avez gagné 500000 FCFA sur Orange Money ! Cliquez ici pour réclamer votre gain."
        val result = detector.analyze("SMS", text)

        assertTrue(result.score >= 30)
        assertTrue(result.signals.any { it.category == "Gain ou loterie non sollicités" })
    }

    @Test
    fun `demande d argent seule sans urgence ni usurpation reste a un score modere`() {
        val text = "Envoie-moi 5000 fcfa stp"
        val result = detector.analyze("SMS", text)

        // Signal réel mais pas de schéma combiné : ne doit pas atteindre CRITICAL.
        assertTrue(result.score > 0)
        assertTrue(result.riskLevel != RiskLevel.CRITICAL)
    }

    @Test
    fun `score ne depasse jamais 100`() {
        val text = "je m'appelle Emmanuel Adebayor, nouveau numéro, c'est urgent, très urgent, envoie-moi " +
            "10000 fcfa via mobile money orange money wave momo, je te renverrai le triple, vous avez gagné " +
            "une loterie, cliquez ici http://192.168.0.1/verify bit.ly/abc whatsapp-secure.xyz, hôpital accident"
        val result = detector.analyze("WhatsApp", text)

        assertTrue(result.score <= 100)
        assertEquals(RiskLevel.CRITICAL, result.riskLevel)
    }
}
