package com.fishguard.mobile.detection

import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Response
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.Body
import retrofit2.http.POST
import retrofit2.http.Url
import java.util.concurrent.TimeUnit

data class AnalyzeRequest(
    val text: String,
    val source_app: String
)

/**
 * Doit correspondre à ce que retourne l'API Flask FishGuard (endpoint /api/analyze
 * côté web). Adapte les noms de champs si ton backend utilise un autre format —
 * c'est la seule classe à modifier pour brancher le vrai backend.
 */
data class AnalyzeResponse(
    val score: Int,
    val classification: String?,
    val explanations: List<String>?
)

interface FishGuardApi {
    @POST
    suspend fun analyze(@Url path: String, @Body request: AnalyzeRequest): AnalyzeResponse
}

/**
 * Construit un client vers le backend FishGuard. L'URL, le chemin de l'endpoint
 * et une éventuelle clé API sont configurables dans les réglages de l'appli —
 * pratique pour brancher aussi bien un serveur Flask en LAN qu'une API en prod
 * protégée par une clé.
 */
class RemoteApiClient(
    private val baseUrl: String,
    private val endpointPath: String = "/api/analyze",
    private val apiKey: String = ""
) {

    private val api: FishGuardApi by lazy {
        val authInterceptor = Interceptor { chain ->
            val request = if (apiKey.isNotBlank()) {
                chain.request().newBuilder()
                    .addHeader("Authorization", "Bearer $apiKey")
                    .addHeader("X-API-Key", apiKey)
                    .build()
            } else {
                chain.request()
            }
            chain.proceed(request)
        }

        val client = OkHttpClient.Builder()
            .connectTimeout(4, TimeUnit.SECONDS)
            .readTimeout(6, TimeUnit.SECONDS)
            .addInterceptor(authInterceptor)
            .build()

        Retrofit.Builder()
            .baseUrl(if (baseUrl.endsWith("/")) baseUrl else "$baseUrl/")
            .client(client)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
            .create(FishGuardApi::class.java)
    }

    private fun normalizedPath(): String = endpointPath.removePrefix("/").ifBlank { "api/analyze" }

    suspend fun analyze(sourceApp: String, text: String): DetectionResult {
        val response = api.analyze(normalizedPath(), AnalyzeRequest(text = text, source_app = sourceApp))
        val score = response.score.coerceIn(0, 100)
        val signals = response.explanations?.map {
            ThreatSignal(category = response.classification ?: "Backend", explanation = it, weight = 0)
        } ?: emptyList()

        return DetectionResult(
            sourceApp = sourceApp,
            originalText = text,
            score = score,
            riskLevel = DetectionResult.scoreToLevel(score),
            signals = signals,
            engine = "backend"
        )
    }

    /** Simple aller-retour utilisé par le bouton "Tester la connexion" des réglages. */
    suspend fun testConnection(): Result<Unit> = try {
        api.analyze(normalizedPath(), AnalyzeRequest(text = "test de connexion FishGuard", source_app = "test"))
        Result.success(Unit)
    } catch (e: Exception) {
        Result.failure(e)
    }
}
