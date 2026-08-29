package com.fishguard.mobile.calls

import android.content.Context
import android.util.Log
import org.vosk.Model
import org.vosk.Recognizer
import org.vosk.android.StorageService
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.zip.ZipInputStream

/**
 * Charge le modèle vocal français et transforme un flux audio en texte,
 * entièrement sur l'appareil (aucun octet audio n'est envoyé où que ce soit).
 *
 * Deux façons d'obtenir le modèle (~45 Mo) :
 *  1. Embarqué dans les assets de l'APK au moment de la compilation (voir
 *     `.github/workflows/build-apk.yml`) — c'est le cas normal, l'app
 *     fonctionne hors ligne dès l'installation.
 *  2. À défaut (ex: build local sans ce script CI), téléchargement unique au
 *     premier lancement de la fonctionnalité, puis mise en cache locale —
 *     ensuite le fonctionnement redevient 100% hors ligne.
 */
class VoskSpeechEngine(private val context: Context) {

    companion object {
        private const val TAG = "FishGuard/Vosk"
        private const val MODEL_ASSET_PATH = "vosk-model-fr"
        private const val MODEL_DOWNLOAD_URL =
            "https://alphacephei.com/vosk/models/vosk-model-small-fr-0.22.zip"
        const val SAMPLE_RATE = 16000f
    }

    sealed class ModelState {
        data object NotReady : ModelState()
        data class Downloading(val progressPercent: Int) : ModelState()
        data object Ready : ModelState()
        data class Error(val message: String) : ModelState()
    }

    private var model: Model? = null
    private var recognizer: Recognizer? = null

    /** true si le modèle est déjà présent (embarqué ou déjà téléchargé une fois). */
    fun isModelAvailableOffline(): Boolean {
        val unpacked = File(context.filesDir, MODEL_ASSET_PATH)
        if (unpacked.exists()) return true
        return runCatching { context.assets.list("")?.contains(MODEL_ASSET_PATH) == true }.getOrDefault(false)
    }

    /**
     * Prépare le modèle : le déballe depuis les assets s'il y est déjà, sinon le
     * télécharge une seule fois. `onProgress` permet d'afficher une barre de
     * progression pendant le téléchargement de secours.
     */
    suspend fun prepareModel(onProgress: (ModelState) -> Unit) {
        val targetDir = File(context.filesDir, MODEL_ASSET_PATH)
        if (targetDir.exists() && targetDir.list()?.isNotEmpty() == true) {
            loadModel(targetDir.absolutePath, onProgress)
            return
        }

        val hasEmbeddedAsset = runCatching {
            context.assets.list("")?.contains(MODEL_ASSET_PATH) == true
        }.getOrDefault(false)

        if (hasEmbeddedAsset) {
            try {
                StorageService.unpack(
                    context, MODEL_ASSET_PATH, "vosk-model",
                    { unpackedModel -> onModelUnpacked(unpackedModel, onProgress) },
                    { exception ->
                        Log.e(TAG, "Échec du déballage du modèle embarqué", exception)
                        onProgress(ModelState.Error("Impossible de charger le modèle vocal embarqué."))
                    }
                )
            } catch (e: Exception) {
                onProgress(ModelState.Error(e.message ?: "Erreur inconnue au chargement du modèle."))
            }
        } else {
            downloadModel(targetDir, onProgress)
        }
    }

    private fun onModelUnpacked(unpackedModel: Model, onProgress: (ModelState) -> Unit) {
        model = unpackedModel
        onProgress(ModelState.Ready)
    }

    private fun loadModel(path: String, onProgress: (ModelState) -> Unit) {
        try {
            model = Model(path)
            onProgress(ModelState.Ready)
        } catch (e: Exception) {
            onProgress(ModelState.Error(e.message ?: "Modèle vocal illisible."))
        }
    }

    private fun downloadModel(targetDir: File, onProgress: (ModelState) -> Unit) {
        try {
            onProgress(ModelState.Downloading(0))
            val connection = URL(MODEL_DOWNLOAD_URL).openConnection() as HttpURLConnection
            connection.connect()
            val totalSize = connection.contentLength.coerceAtLeast(1)

            val zipFile = File(context.cacheDir, "vosk-model-fr.zip")
            connection.inputStream.use { input ->
                FileOutputStream(zipFile).use { output ->
                    val buffer = ByteArray(8192)
                    var readTotal = 0
                    var read: Int
                    while (input.read(buffer).also { read = it } != -1) {
                        output.write(buffer, 0, read)
                        readTotal += read
                        onProgress(ModelState.Downloading((readTotal * 100 / totalSize).coerceIn(0, 100)))
                    }
                }
            }

            targetDir.mkdirs()
            ZipInputStream(zipFile.inputStream()).use { zip ->
                var entry = zip.nextEntry
                while (entry != null) {
                    // Les modèles Vosk sont zippés avec un dossier racine (ex: vosk-model-small-fr-0.22/) :
                    // on l'aplatit pour que targetDir contienne directement les fichiers du modèle.
                    val relativePath = entry.name.substringAfter('/')
                    if (relativePath.isNotBlank()) {
                        val outFile = File(targetDir, relativePath)
                        if (entry.isDirectory) {
                            outFile.mkdirs()
                        } else {
                            outFile.parentFile?.mkdirs()
                            FileOutputStream(outFile).use { zip.copyTo(it) }
                        }
                    }
                    entry = zip.nextEntry
                }
            }
            zipFile.delete()

            loadModel(targetDir.absolutePath, onProgress)
        } catch (e: Exception) {
            Log.e(TAG, "Échec du téléchargement du modèle vocal", e)
            onProgress(ModelState.Error("Téléchargement impossible — vérifie ta connexion et réessaie."))
        }
    }

    /** À appeler une fois le modèle prêt, avant de commencer à transcrire. */
    fun startRecognizer() {
        val currentModel = model ?: return
        recognizer = Recognizer(currentModel, SAMPLE_RATE)
    }

    /**
     * Traite un bloc audio PCM 16-bit. Retourne le texte final reconnu quand
     * une phrase se termine (silence détecté), ou null si la phrase continue.
     */
    fun acceptAudio(buffer: ShortArray, length: Int): String? {
        val rec = recognizer ?: return null
        val isFinal = rec.acceptWaveForm(buffer, length)
        return if (isFinal) extractText(rec.result) else null
    }

    /** Texte partiel de la phrase en cours de prononciation (retour visuel en direct). */
    fun partialText(): String {
        val rec = recognizer ?: return ""
        return extractText(rec.partialResult, key = "partial")
    }

    private fun extractText(json: String, key: String = "text"): String {
        return runCatching {
            val marker = "\"$key\""
            val idx = json.indexOf(marker)
            if (idx == -1) return ""
            val colon = json.indexOf(':', idx)
            val firstQuote = json.indexOf('"', colon + 1)
            val secondQuote = json.indexOf('"', firstQuote + 1)
            if (firstQuote == -1 || secondQuote == -1) "" else json.substring(firstQuote + 1, secondQuote)
        }.getOrDefault("")
    }

    fun release() {
        recognizer?.close()
        recognizer = null
        model?.close()
        model = null
    }
}
