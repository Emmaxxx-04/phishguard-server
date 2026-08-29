package com.fishguard.mobile

import android.Manifest
import android.app.role.RoleManager
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
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
import androidx.lifecycle.lifecycleScope
import com.fishguard.mobile.ui.navigation.FishGuardNavHost
import com.fishguard.mobile.ui.onboarding.OnboardingScreen
import com.fishguard.mobile.ui.splash.SplashScreen
import com.fishguard.mobile.ui.theme.FishGuardTheme
import kotlinx.coroutines.launch

private enum class LaunchStage { SPLASH, READY }

class MainActivity : ComponentActivity() {

    private var notificationAccessGranted by mutableStateOf(false)

    private val smsPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { /* résultats gérés implicitement : le SmsReceiver ne reçoit rien sans permission */ }

    private val postNotifPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { }

    private val callScreeningRoleLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { /* l'utilisateur a accepté ou refusé depuis la boîte de dialogue système */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val app = application as FishGuardApp

        setContent {
            val onboardingDone by app.settingsRepository.onboardingDone.collectAsState(initial = null)
            val themeModeStr by app.settingsRepository.themeMode.collectAsState(initial = "SYSTEM")
            val systemDark = isSystemInDarkTheme()
            val darkTheme = when (themeModeStr) {
                "LIGHT" -> false
                "DARK" -> true
                else -> systemDark
            }

            var stage by remember { mutableStateOf(LaunchStage.SPLASH) }

            FishGuardTheme(darkTheme = darkTheme) {
                Surface(modifier = Modifier.fillMaxSize()) {
                    when {
                        stage == LaunchStage.SPLASH -> SplashScreen(onFinished = { stage = LaunchStage.READY })
                        onboardingDone == null -> Unit // état encore inconnu (chargement DataStore) : ne rien afficher pour éviter un flash
                        onboardingDone == false -> OnboardingScreen(onContinue = {
                            lifecycleScope.launch { app.settingsRepository.setOnboardingDone(true) }
                            requestRuntimePermissions()
                        })
                        else -> FishGuardNavHost(
                            app = app,
                            notificationAccessGranted = notificationAccessGranted,
                            onOpenNotificationSettings = ::openNotificationAccessSettings,
                            onRequestCallScreeningRole = ::requestCallScreeningRole,
                            onOpenFullScreenIntentSettings = ::openFullScreenIntentSettings
                        )
                    }
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        notificationAccessGranted = isNotificationServiceEnabled()
    }

    private fun requestRuntimePermissions() {
        val permissions = mutableListOf(
            Manifest.permission.RECEIVE_SMS,
            Manifest.permission.READ_SMS,
            Manifest.permission.READ_PHONE_STATE,
            Manifest.permission.READ_CONTACTS
        )
        smsPermissionLauncher.launch(permissions.toTypedArray())

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                postNotifPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    private fun openNotificationAccessSettings() {
        startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
    }

    private fun requestCallScreeningRole() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val roleManager = getSystemService(RoleManager::class.java)
            if (roleManager != null && roleManager.isRoleAvailable(RoleManager.ROLE_CALL_SCREENING)) {
                if (!roleManager.isRoleHeld(RoleManager.ROLE_CALL_SCREENING)) {
                    callScreeningRoleLauncher.launch(roleManager.createRequestRoleIntent(RoleManager.ROLE_CALL_SCREENING))
                }
                return
            }
        }
        // Avant Android 10 (pas de RoleManager) : on oriente vers la fiche appli,
        // où l'utilisateur peut choisir FishGuard manuellement selon son fabricant.
        val intent = Intent(
            Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
            android.net.Uri.fromParts("package", packageName, null)
        )
        startActivity(intent)
    }

    private fun isNotificationServiceEnabled(): Boolean {
        val enabledListeners = Settings.Secure.getString(contentResolver, "enabled_notification_listeners")
        return enabledListeners?.contains(packageName) == true
    }

    /**
     * Sur Android 14+, l'affichage du pop-up plein écran pour un numéro inconnu
     * n'est pas garanti automatiquement — ce réglage système (habituellement
     * utilisé par les apps d'alarme/réveil) doit être accordé explicitement.
     */
    private fun openFullScreenIntentSettings() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val intent = Intent(Settings.ACTION_MANAGE_APP_USE_FULL_SCREEN_INTENT).apply {
                data = android.net.Uri.fromParts("package", packageName, null)
            }
            startActivity(intent)
        } else {
            val intent = Intent(
                Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                android.net.Uri.fromParts("package", packageName, null)
            )
            startActivity(intent)
        }
    }
}
