package me.usersu.manager.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import me.usersu.manager.data.DAEMON_SOCKETS
import me.usersu.manager.data.StatusPayload

/**
 * The Settings tab.
 *
 * Everything here is read-only information about the running daemon plus the
 * two lifecycle actions.  Editing the configuration is deliberately not offered
 * until the corresponding protocol request is implemented, so the screen never
 * shows a control that silently does nothing.
 */
@Composable
fun SettingsScreen(
    status: StatusPayload,
    onRefresh: () -> Unit,
    onShutdown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Card {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("Daemon", style = MaterialTheme.typography.titleMedium)
                Field("layout", status.layout)
                Field("userfs", status.userfs)
                Field("profile", status.profile)
                Field("root", if (status.root) "yes" else "no")
                Field("euid", status.euid.toString())
                Field("kernel", status.kernel)
                Field("arch", status.arch)
            }
        }

        Card {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("Sockets", style = MaterialTheme.typography.titleMedium)
                DAEMON_SOCKETS.forEach { Field("path", it) }
            }
        }

        Button(onClick = onRefresh) { Text("Refresh status") }
        OutlinedButton(onClick = onShutdown) { Text("Stop usud") }
    }
}
