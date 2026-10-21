package me.usersu.manager.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * The UserFS tab: a read-mostly browser for the merged layer tree.
 *
 * Entries are listed as usud reports them.  A trailing `/` marks a directory,
 * which is the only type information the listing protocol carries; the browser
 * therefore does not guess further and lets the user descend into anything.
 */
@Composable
fun UserfsScreen(
    path: String,
    entries: List<String>,
    onOpen: (String) -> Unit,
    onUp: () -> Unit,
    onReload: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxSize()) {
        Column(Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
            Text("UserFS", style = MaterialTheme.typography.headlineSmall)
            Text(
                path.ifEmpty { "/" },
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        LazyColumn(Modifier.fillMaxSize()) {
            item {
                ListItem(
                    headlineContent = { Text("..") },
                    leadingContent = {
                        IconButton(onClick = onUp) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Up")
                        }
                    },
                    trailingContent = {
                        TextButton(onClick = onReload) { Text("Reload") }
                    },
                )
            }
            items(entries, key = { it }) { entry ->
                val isDir = entry.endsWith("/")
                val name = entry.trimEnd('/')
                ListItem(
                    modifier = Modifier.fillMaxWidth().clickable(enabled = isDir) {
                        if (isDir) onOpen(joinPath(path, name))
                    },
                    headlineContent = { Text(entry) },
                    leadingContent = {
                        Icon(
                            if (isDir) Icons.Filled.Folder else Icons.Filled.Description,
                            contentDescription = null,
                        )
                    },
                )
            }
            if (entries.isEmpty()) {
                item {
                    Text(
                        "empty",
                        modifier = Modifier.padding(16.dp),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

/** Joins a directory and a child, keeping a single separator. */
internal fun joinPath(parent: String, child: String): String {
    val base = if (parent.isEmpty() || parent == "/") "/" else parent.trimEnd('/') + "/"
    return base + child
}
