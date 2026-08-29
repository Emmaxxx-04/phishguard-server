package com.fishguard.mobile.calls

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat
import androidx.lifecycle.viewmodel.compose.viewModel
import com.fishguard.mobile.FishGuardApp
import com.fishguard.mobile.ui.FishGuardViewModelFactory
import com.fishguard.mobile.ui.calls.CallConsentScreen
import com.fishguard.mobile.ui.calls.CallProtectionLiveScreen
import com.fishguard.mobile.ui.calls.CallSummaryScreen
import com.fishguard.mobile.ui.calls.ScamNumbersViewModel
import com.fishguard.mobile.ui.theme.FishGuardTheme

private enum class ProtectionStage { CONSENT, LIVE, SUMMARY }

/**
 * Écran autonome lancé depuis la notification "Numéro inconnu". Trois étapes :
 * consentement explicite → suivi en direct → résumé de fin d'appel, où c'est
 * l'utilisateur — pas le score — qui décide en dernier ressort si le numéro
 * mérite d'être signalé.
 */
class CallProtectionActivity : ComponentActivity() {

    private val micPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* le démarrage effectif est déclenché après, via ensureMicPermissionThenStart */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.O_MR1) {
            @Suppress("DEPRECATION")
            window.addFlags(
                android.view.WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or
                    android.view.WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON or
                    android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON
            )
        }

        val callerNumber = intent?.getStringExtra("caller_number") ?: ""
        val isUnknownNumber = intent?.getBooleanExtra("is_unknown_number", false) ?: false
        val app = application as FishGuardApp

        setContent {
            val themeModeStr by app.settingsRepository.themeMode.collectAsState(initial = "SYSTEM")
            val systemDark = isSystemInDarkTheme()
            val darkTheme = when (themeModeStr) {
                "LIGHT" -> false
                "DARK" -> true
                else -> systemDark
            }
            var stage by remember { mutableStateOf(ProtectionStage.CONSENT) }
            var lastServiceState by remember { mutableStateOf(CallProtectionState()) }
            val serviceState by CallProtectionService.state.collectAsState()
            val factory = remember { FishGuardViewModelFactory(app) }
            val scamNumbersViewModel: ScamNumbersViewModel = viewModel(factory = factory)

            FishGuardTheme(darkTheme = darkTheme) {
                Surface(modifier = Modifier.fillMaxSize()) {
                    when (stage) {
                        ProtectionStage.CONSENT -> CallConsentScreen(
                            callerNumber = callerNumber,
                            isUnknownNumber = isUnknownNumber,
                            onConfirm = {
                                stage = ProtectionStage.LIVE
                                ensureMicPermissionThenStart(callerNumber)
                            },
                            onCancel = { finish() }
                        )
                        ProtectionStage.LIVE -> CallProtectionLiveScreen(
                            state = serviceState,
                            onStop = {
                                lastServiceState = serviceState
                                stopProtectionService()
                                stage = ProtectionStage.SUMMARY
                            }
                        )
                        ProtectionStage.SUMMARY -> CallSummaryScreen(
                            callerNumber = callerNumber,
                            finalScore = lastServiceState.score,
                            finalRiskLevel = lastServiceState.riskLevel,
                            signalCategories = lastServiceState.signalCategories,
                            onReportConfirmed = { note ->
                                scamNumbersViewModel.report(
                                    number = callerNumber,
                                    note = note,
                                    confirmed = true,
                                    source = "CALL_ANALYSIS",
                                    linkedScore = lastServiceState.score
                                )
                                finish()
                            },
                            onDismiss = { finish() }
                        )
                    }
                }
            }
        }
    }

    private fun ensureMicPermissionThenStart(callerNumber: String) {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO)
            == PackageManager.PERMISSION_GRANTED
        ) {
            startProtectionService(callerNumber)
        } else {
            micPermissionLauncher.launch(Manifest.permission.RECORD_AUDIO)
            // Dès l'octroi, l'utilisateur retape "démarrer" si besoin ; on tente
            // aussi un démarrage immédiat au cas où le système répond assez vite.
            startProtectionService(callerNumber)
        }
    }

    private fun startProtectionService(callerNumber: String) {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO)
            != PackageManager.PERMISSION_GRANTED
        ) return
        val intent = Intent(this, CallProtectionService::class.java).apply {
            putExtra("caller_number", callerNumber)
        }
        ContextCompat.startForegroundService(this, intent)
    }

    private fun stopProtectionService() {
        val intent = Intent(this, CallProtectionService::class.java).apply {
            action = CallProtectionService.ACTION_STOP
        }
        startService(intent)
    }
}
