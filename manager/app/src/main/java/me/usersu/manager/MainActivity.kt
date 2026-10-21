package me.usersu.manager

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import me.usersu.manager.data.ManagerViewModel
import me.usersu.manager.data.UiState
import me.usersu.manager.ui.screens.HomeScreen
import me.usersu.manager.ui.screens.SettingsScreen
import me.usersu.manager.ui.screens.SuperuserScreen
import me.usersu.manager.ui.screens.UserfsScreen
import me.usersu.manager.ui.theme.UserSUTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            UserSUTheme {
                ManagerApp()
            }
        }
    }
}

/** One destination in the bottom navigation bar. */
private enum class Tab(val labelRes: Int, val icon: ImageVector) {
    Home(R.string.nav_home, Icons.Filled.Home),
    Superuser(R.string.nav_superuser, Icons.Filled.Security),
    Userfs(R.string.nav_userfs, Icons.Filled.Folder),
    Settings(R.string.nav_settings, Icons.Filled.Settings),
}

@Composable
private fun ManagerApp(viewModel: ManagerViewModel = viewModel()) {
    var tab by rememberSaveable { mutableIntStateOf(0) }
    val state by viewModel.state.collectAsStateWithLifecycle()
    val notice by viewModel.notice.collectAsStateWithLifecycle()
    val browser by viewModel.browser.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }

    // Load the UserFS root the first time the browser tab is opened.
    LaunchedEffect(tab) {
        if (Tab.entries[tab] == Tab.Userfs && browser.entries.isEmpty() && browser.error == null) {
            viewModel.browse("/")
        }
    }

    LaunchedEffect(notice) {
        notice?.let {
            snackbar.showSnackbar(it.text)
            viewModel.consumeNotice()
        }
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbar) },
        bottomBar = {
            NavigationBar {
                Tab.entries.forEachIndexed { index, entry ->
                    NavigationBarItem(
                        selected = tab == index,
                        onClick = { tab = index },
                        icon = { Icon(entry.icon, contentDescription = null) },
                        label = { Text(stringResource(entry.labelRes)) },
                    )
                }
            }
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (val current = state) {
                is UiState.Loading -> Box(Modifier.fillMaxSize(), Alignment.Center) {
                    CircularProgressIndicator()
                }

                is UiState.Unavailable -> UnavailableNotice(current.reason, viewModel::refresh)

                is UiState.Ready -> when (Tab.entries[tab]) {
                    Tab.Home -> HomeScreen(
                        status = current.status,
                        providers = current.providers,
                        onBootInit = viewModel::bootInit,
                        onRefresh = viewModel::refresh,
                    )

                    Tab.Superuser -> SuperuserScreen(
                        profiles = current.profiles,
                        onActivate = viewModel::activateProfile,
                    )

                    Tab.Userfs -> UserfsScreen(
                        path = browser.path,
                        entries = browser.entries,
                        onOpen = viewModel::browse,
                        onUp = { viewModel.browse(parentOf(browser.path)) },
                        onReload = { viewModel.browse(browser.path) },
                    )

                    Tab.Settings -> SettingsScreen(
                        status = current.status,
                        onRefresh = viewModel::refresh,
                        onShutdown = viewModel::shutdown,
                    )
                }
            }
        }
    }
}

@Composable
private fun UnavailableNotice(reason: String, onRetry: () -> Unit) {
    Box(Modifier.fillMaxSize(), Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text("usud is not reachable", style = MaterialTheme.typography.titleMedium)
            Text(reason, style = MaterialTheme.typography.bodySmall)
            TextButton(onClick = onRetry) { Text("Retry") }
        }
    }
}

/** The parent of a UserFS path, clamped at `/`. */
internal fun parentOf(path: String): String {
    val trimmed = path.trimEnd('/')
    if (trimmed.isEmpty()) return "/"
    val cut = trimmed.lastIndexOf('/')
    return if (cut <= 0) "/" else trimmed.substring(0, cut)
}
