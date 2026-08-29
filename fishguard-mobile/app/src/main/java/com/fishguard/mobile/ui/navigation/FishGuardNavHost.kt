package com.fishguard.mobile.ui.navigation

import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.List
import androidx.compose.material.icons.filled.MenuBook
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.fishguard.mobile.FishGuardApp
import com.fishguard.mobile.ui.FishGuardViewModelFactory
import com.fishguard.mobile.ui.calls.ScamNumbersScreen
import com.fishguard.mobile.ui.calls.ScamNumbersViewModel
import com.fishguard.mobile.ui.dashboard.DashboardScreen
import com.fishguard.mobile.ui.dashboard.DashboardViewModel
import com.fishguard.mobile.ui.learn.LearnScreen
import com.fishguard.mobile.ui.manualtest.ManualTestScreen
import com.fishguard.mobile.ui.manualtest.ManualTestViewModel
import com.fishguard.mobile.ui.settings.SettingsScreen
import com.fishguard.mobile.ui.settings.SettingsViewModel
import com.fishguard.mobile.ui.threats.ThreatDetailScreen
import com.fishguard.mobile.ui.threats.ThreatListScreen
import com.fishguard.mobile.ui.threats.ThreatListViewModel

private sealed class Dest(val route: String, val label: String) {
    data object Dashboard : Dest("dashboard", "Accueil")
    data object Threats : Dest("threats", "Historique")
    data object Learn : Dest("learn", "Apprendre")
    data object Settings : Dest("settings", "Réglages")
}

/** Routes accessibles depuis un onglet mais empilées par-dessus (ont besoin d'une flèche retour). */
private const val ROUTE_THREAT_DETAIL = "threat_detail/{id}"
private const val ROUTE_MANUAL_TEST = "manual_test"
private const val ROUTE_SCAM_NUMBERS = "scam_numbers"

@Composable
fun FishGuardNavHost(
    app: FishGuardApp,
    notificationAccessGranted: Boolean,
    onOpenNotificationSettings: () -> Unit,
    onRequestCallScreeningRole: () -> Unit,
    onOpenFullScreenIntentSettings: () -> Unit
) {
    val navController = rememberNavController()
    val factory = remember { FishGuardViewModelFactory(app) }
    val tabs = listOf(Dest.Dashboard, Dest.Threats, Dest.Learn, Dest.Settings)

    val backStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = backStackEntry?.destination?.route
    val showBottomBar = tabs.any { it.route == currentRoute }

    Scaffold(
        bottomBar = {
            if (showBottomBar) {
                NavigationBar {
                    val currentDestination = backStackEntry?.destination
                    tabs.forEach { dest ->
                        val icon = when (dest) {
                            Dest.Dashboard -> Icons.Filled.Home
                            Dest.Threats -> Icons.Filled.List
                            Dest.Learn -> Icons.Filled.MenuBook
                            Dest.Settings -> Icons.Filled.Settings
                        }
                        NavigationBarItem(
                            selected = currentDestination?.hierarchy?.any { it.route == dest.route } == true,
                            onClick = {
                                navController.navigate(dest.route) {
                                    popUpTo(navController.graph.findStartDestination().id) { saveState = true }
                                    launchSingleTop = true
                                    restoreState = true
                                }
                            },
                            icon = { Icon(icon, contentDescription = dest.label) },
                            label = { Text(dest.label) }
                        )
                    }
                }
            }
        }
    ) { padding ->
        NavHost(
            navController = navController,
            startDestination = Dest.Dashboard.route,
            modifier = Modifier.padding(if (showBottomBar) padding else PaddingValues(0.dp))
        ) {
            composable(Dest.Dashboard.route) {
                val vm: DashboardViewModel = viewModel(factory = factory)
                DashboardScreen(
                    viewModel = vm,
                    notificationAccessGranted = notificationAccessGranted,
                    onOpenThreat = { id -> navController.navigate("threat_detail/$id") },
                    onOpenNotificationSettings = onOpenNotificationSettings,
                    onOpenManualTest = { navController.navigate(ROUTE_MANUAL_TEST) }
                )
            }
            composable(Dest.Threats.route) {
                val vm: ThreatListViewModel = viewModel(factory = factory)
                ThreatListScreen(viewModel = vm, onOpenThreat = { id -> navController.navigate("threat_detail/$id") })
            }
            composable(Dest.Learn.route) {
                LearnScreen()
            }
            composable(Dest.Settings.route) {
                val vm: SettingsViewModel = viewModel(factory = factory)
                SettingsScreen(
                    viewModel = vm,
                    notificationAccessGranted = notificationAccessGranted,
                    onOpenNotificationSettings = onOpenNotificationSettings,
                    onRequestCallScreeningRole = onRequestCallScreeningRole,
                    onOpenFullScreenIntentSettings = onOpenFullScreenIntentSettings,
                    onOpenScamNumbers = { navController.navigate(ROUTE_SCAM_NUMBERS) }
                )
            }
            composable(ROUTE_THREAT_DETAIL) { backStackEntryArg ->
                val id = backStackEntryArg.arguments?.getString("id")?.toLongOrNull() ?: return@composable
                ThreatDetailScreen(app = app, threatId = id, onBack = { navController.popBackStack() })
            }
            composable(ROUTE_MANUAL_TEST) {
                val vm: ManualTestViewModel = viewModel(factory = factory)
                ManualTestScreen(viewModel = vm, onBack = { navController.popBackStack() })
            }
            composable(ROUTE_SCAM_NUMBERS) {
                val vm: ScamNumbersViewModel = viewModel(factory = factory)
                ScamNumbersScreen(viewModel = vm, onBack = { navController.popBackStack() })
            }
        }
    }
}
