package com.fishguard.mobile.calls

import android.content.Context
import android.net.Uri
import android.provider.ContactsContract

/**
 * Détermine si un numéro appelant correspond à un contact déjà enregistré sur
 * le téléphone. Sert uniquement à décider si on propose l'analyse (réservée
 * aux numéros inconnus) — le nom du contact lui-même n'est jamais lu ni
 * stocké par FishGuard.
 */
object ContactsLookup {

    fun isKnownContact(context: Context, rawNumber: String): Boolean {
        if (rawNumber.isBlank()) return false

        return try {
            val uri = Uri.withAppendedPath(
                ContactsContract.PhoneLookup.CONTENT_FILTER_URI,
                Uri.encode(rawNumber)
            )
            context.contentResolver.query(
                uri,
                arrayOf(ContactsContract.PhoneLookup._ID),
                null, null, null
            )?.use { cursor -> cursor.moveToFirst() } ?: false
        } catch (e: SecurityException) {
            // Permission non accordée : on considère le numéro comme "inconnu"
            // par défaut, pour ne jamais bloquer silencieusement l'analyse.
            false
        } catch (e: Exception) {
            false
        }
    }
}
