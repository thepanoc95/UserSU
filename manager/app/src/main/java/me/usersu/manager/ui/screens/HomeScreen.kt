package me.usersu.manager.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import me.usersu.manager.data.ProviderInfo
import me.usersu.manager.data.StatusPayload

/**
 * The Home tab: what usud is, what it found, and the two actions a user takes
 * first (start an init sandbox, or refresh the probe).
 */
@Composable
fun HomeScreen(
    status: StatusPayload,
    providers: List<ProviderInfo>,
    onBootInit: () -> Unit,
    onRefresh: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        StatusCard(status)

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Privilege providers", style = MaterialTheme.typography.titleMedium)
                if (providers.isEmpty()) {
                    Text("No providers reported.", style = MaterialTheme.typography.bodyMedium)
                }
                providers.forEach { ProviderRow(it) }
            }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(onClick = onBootInit) { Text("Boot init sandbox") }
            Button(onClick = onRefresh) { Text("Refresh") }
        }
    }
}

@Composable
private fun StatusCard(status: StatusPayload) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("UserSU", style = MaterialTheme.typography.headlineSmall)
            Text(
                if (status.root) "running with root" else "running unprivileged",
                color = MaterialTheme.colorScheme.primary,
                fontWeight = FontWeight.SemiBold,
            )
            Spacer(Modifier.height(4.dp))
            Field("Layout", status.layout)
            Field("UserFS", status.userfs)
            Field("Profile", status.profile)
            Field("Kernel", status.kernel)
            Field("Architecture", status.arch)
            Field("Init", if (status.initRunning) "running" else "stopped")
            Field("usud", "v${status.version} (euid ${status.euid})")
        }
    }
}

@Composable
private fun ProviderRow(provider: ProviderInfo) {
    Column {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(provider.name, style = MaterialTheme.typography.bodyLarge)
            Text(
                if (provider.available) "available" else "unavailable",
                style = MaterialTheme.typography.labelLarge,
                color = if (provider.available) {
                    MaterialTheme.colorScheme.primary
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                },
            )
        }
        Text(provider.kind, style = MaterialTheme.typography.labelSmall)
        provider.reason?.let {
            Text(it, style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
internal fun Field(label: String, value: String) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, style = MaterialTheme.typography.bodyMedium)
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
