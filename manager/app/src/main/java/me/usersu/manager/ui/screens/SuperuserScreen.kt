package me.usersu.manager.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import me.usersu.manager.data.ProfileInfo

/**
 * The Superuser tab: the active profile's privileges.
 *
 * usud grants `su` to the UIDs listed in the configuration.  This tab shows
 * which profile is active and lets the user switch between isolated UserFS
 * trees; per-app grants are edited in the configuration file, which the daemon
 * owns, so the app does not pretend to write them itself.
 */
@Composable
fun SuperuserScreen(
    profiles: List<ProfileInfo>,
    onActivate: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxSize().padding(16.dp)) {
        Text("Profiles", style = MaterialTheme.typography.headlineSmall)
        Text(
            "Each profile is an isolated UserFS tree. The active profile applies to every new su request.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(top = 12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            items(profiles, key = { it.name }) { profile ->
                ProfileCard(profile, onActivate)
            }
        }
    }
}

@Composable
private fun ProfileCard(profile: ProfileInfo, onActivate: (String) -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text(profile.name, style = MaterialTheme.typography.titleMedium)
                Field("upper", profile.upper)
                Field("work", profile.work)
                if (profile.lower.isNotEmpty()) {
                    Field("lower", profile.lower.joinToString())
                }
                Field("rw /user_system", if (profile.rwUserSystem) "yes" else "no")
            }
            AssistChip(
                onClick = { onActivate(profile.name) },
                enabled = !profile.active,
                label = { Text(if (profile.active) "active" else "activate") },
            )
        }
    }
}
