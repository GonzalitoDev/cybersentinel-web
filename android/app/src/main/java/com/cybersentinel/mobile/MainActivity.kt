package com.cybersentinel.mobile

import android.app.Application
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.enableEdgeToEdge
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.cybersentinel.mobile.data.Database
import com.cybersentinel.mobile.ui.screens.AppsScreen
import com.cybersentinel.mobile.ui.screens.FilesScreen
import com.cybersentinel.mobile.ui.screens.FindingDetailScreen
import com.cybersentinel.mobile.ui.screens.HistoryScreen
import com.cybersentinel.mobile.ui.screens.HomeScreen
import com.cybersentinel.mobile.ui.screens.LogScreen
import com.cybersentinel.mobile.ui.screens.QuarantineScreen
import com.cybersentinel.mobile.ui.screens.ReportScreen
import com.cybersentinel.mobile.ui.screens.ScanScreen
import com.cybersentinel.mobile.ui.screens.SettingsScreen
import com.cybersentinel.mobile.ui.theme.CsColors
import com.cybersentinel.mobile.ui.theme.CyberSentinelTheme

class CyberSentinelApp : Application() {
    override fun onCreate() {
        super.onCreate()
        // Abre (y crea si hace falta) la base local al iniciar.
        Database.get(this).writableDatabase
    }
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT)
        )
        setContent {
            CyberSentinelTheme { AppRoot() }
        }
    }
}

object Routes {
    const val HOME = "home"
    const val FILES = "files"
    const val APPS = "apps"
    const val HISTORY = "history"
    const val SETTINGS = "settings"
    const val SCAN = "scan"
    const val QUARANTINE = "quarantine"
    const val LOG = "log"
    fun report(id: Long) = "report/$id"
    fun finding(id: Long) = "finding/$id"
}

private data class Tab(val route: String, val label: String, val icon: ImageVector)

private val tabs = listOf(
    Tab(Routes.HOME, "Inicio", Icons.Filled.Home),
    Tab(Routes.FILES, "Archivos", Icons.Filled.Search),
    Tab(Routes.APPS, "Apps", Icons.Filled.Build),
    Tab(Routes.HISTORY, "Historial", Icons.AutoMirrored.Filled.List),
    Tab(Routes.SETTINGS, "Ajustes", Icons.Filled.Settings)
)

@Composable
fun AppRoot() {
    val nav = rememberNavController()
    val backStack by nav.currentBackStackEntryAsState()
    val current = backStack?.destination?.route
    val showBar = tabs.any { it.route == current }

    Scaffold(
        containerColor = CsColors.Background,
        bottomBar = {
            if (showBar) NavigationBar(containerColor = CsColors.Surface) {
                tabs.forEach { t ->
                    NavigationBarItem(
                        selected = current == t.route,
                        onClick = { nav.goTab(t.route) },
                        icon = { Icon(t.icon, contentDescription = t.label) },
                        label = { Text(t.label) },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = CsColors.Green,
                            selectedTextColor = CsColors.Green,
                            indicatorColor = CsColors.Green.copy(alpha = 0.12f),
                            unselectedIconColor = CsColors.TextDim,
                            unselectedTextColor = CsColors.TextDim
                        )
                    )
                }
            }
        }
    ) { padding ->
        NavHost(nav, startDestination = Routes.HOME, modifier = Modifier.padding(padding)) {
            composable(Routes.HOME) { HomeScreen(nav) }
            composable(Routes.FILES) { FilesScreen(nav) }
            composable(Routes.APPS) { AppsScreen(nav) }
            composable(Routes.HISTORY) { HistoryScreen(nav) }
            composable(Routes.SETTINGS) { SettingsScreen(nav) }
            composable(Routes.SCAN) { ScanScreen(nav) }
            composable(Routes.QUARANTINE) { QuarantineScreen(nav) }
            composable(Routes.LOG) { LogScreen(nav) }
            composable("report/{id}", arguments = listOf(navArgument("id") { type = NavType.LongType })) {
                ReportScreen(nav, it.arguments?.getLong("id") ?: 0L)
            }
            composable("finding/{id}", arguments = listOf(navArgument("id") { type = NavType.LongType })) {
                FindingDetailScreen(nav, it.arguments?.getLong("id") ?: 0L)
            }
        }
    }
}

fun NavHostController.goTab(route: String) {
    navigate(route) {
        popUpTo(graph.findStartDestination().id) { saveState = true }
        launchSingleTop = true
        restoreState = true
    }
}
