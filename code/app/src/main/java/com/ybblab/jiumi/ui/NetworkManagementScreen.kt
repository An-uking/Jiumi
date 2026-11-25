// SPDX-FileCopyrightText: 2026 ybblab
// SPDX-License-Identifier: Apache-2.0

package com.ybblab.jiumi.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.ybblab.jiumi.MonitorController
import com.ybblab.jiumi.R
import com.ybblab.jiumi.data.ManagedNetworkApp
import com.ybblab.jiumi.ui.icons.JiumiIcons
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
internal fun NetworkManagementScreen(controller: MonitorController, labels: AppLabels, onBack: () -> Unit) {
    val management = controller.networkManagement
    val policy by management.state.collectAsStateWithLifecycle()
    val monitor by controller.state.collectAsStateWithLifecycle()
    val autoRestore = policy.restoreEnabledAtBoot != null
    val boot = management.boot
    val scope = rememberCoroutineScope()
    var query by rememberSaveable { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var failure by remember { mutableStateOf<Pair<String?, Int>?>(null) }
    var removal by remember { mutableStateOf<ManagedNetworkApp?>(null) }
    val names by produceState(emptyMap<String, String>(), policy.apps.keys, labels) {
        value = withContext(Dispatchers.IO) { policy.apps.mapValues { (_, app) -> labels.label(app.key) } }
    }
    val search = query.trim()
    val apps = remember(policy.apps, names, search) {
        policy.apps.values.filter { it.pkg.contains(search, ignoreCase = true) ||
            names[it.pkg]?.contains(search, ignoreCase = true) == true }
            .sortedBy { (names[it.pkg] ?: it.pkg).lowercase() }
    }
    fun change(failureMessage: Int, pkg: String? = null, update: suspend () -> Boolean) {
        if (busy) return
        busy = true
        failure = null
        scope.launch {
            try {
                if (!update()) failure = pkg to failureMessage
            } finally {
                busy = false
            }
        }
    }
    SubScreen(stringResource(R.string.network_management_title), onBack) { padding ->
        LazyColumn(Modifier.fillMaxSize().padding(padding), contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)) {
            item(key = "restore") {
                val enabled = !busy && (boot != null || autoRestore)
                val toggle: (Boolean) -> Unit = {
                    change(R.string.network_management_save_error) { management.setAutoRestore(it) }
                }
                Card {
                    ListRow(stringResource(R.string.network_management_restore),
                        leading = { IconTile(JiumiIcons.Network) },
                        onClick = if (enabled) ({ toggle(!autoRestore) }) else null) {
                        JiumiSwitch(autoRestore, enabled, toggle)
                    }
                }
                GroupFooter(stringResource(R.string.network_management_restore_desc))
                failure?.takeIf { it.first == null }?.let { GroupFooter(stringResource(it.second), warning = true) }
            }
            if (policy.apps.isNotEmpty()) item(key = "search") { SearchField(query) { query = it } }
            if (apps.isEmpty()) item(key = "empty") {
                EmptyCard(stringResource(if (policy.apps.isEmpty()) R.string.network_management_empty else R.string.apps_empty_search))
            }
            items(apps, key = { it.pkg }) { app ->
                val status = when {
                    !app.blocked -> R.string.access_not_blocked
                    boot == app.verifiedBoot -> R.string.network_management_block_verified
                    boot == null -> R.string.network_management_status_unknown
                    app.pkg in policy.restoreFailures -> R.string.network_management_restore_failed
                    policy.shouldRestore(app, boot) -> R.string.network_management_restore_pending
                    else -> R.string.network_management_not_restored
                }
                val canChange = !busy && monitor.running
                val toggle: (Boolean) -> Unit = {
                    change(R.string.network_management_change_error, app.pkg) { management.setBlocked(app, it) }
                }
                Card {
                    ListRow(names[app.pkg] ?: app.pkg, app.pkg, leading = { AppIcon(labels, app.pkg, 32) })
                    InsetDivider()
                    ListRow(stringResource(R.string.network_management_block), stringResource(status),
                        onClick = if (canChange) ({ toggle(!app.blocked) }) else null) {
                        JiumiSwitch(app.blocked, canChange, toggle)
                    }
                    InsetDivider()
                    ListRow(stringResource(R.string.network_management_remove),
                        onClick = if (!busy) ({ removal = app }) else null)
                }
                failure?.takeIf { it.first == app.pkg }?.let { GroupFooter(stringResource(it.second), warning = true) }
            }
        }
    }
    removal?.let { app ->
        AlertDialog(
            onDismissRequest = { removal = null },
            title = { Text(stringResource(R.string.network_management_remove)) },
            text = { Text(stringResource(R.string.network_management_remove_desc, names[app.pkg] ?: app.pkg)) },
            dismissButton = { TextButton(onClick = { removal = null }) { Text(stringResource(R.string.action_cancel)) } },
            confirmButton = {
                TextButton(onClick = {
                    removal = null
                    change(if (app.blocked && !monitor.running) R.string.network_management_connect
                        else R.string.network_management_change_error, app.pkg) { management.remove(app) }
                }) { Text(stringResource(R.string.network_management_remove)) }
            }
        )
    }
}
