// SPDX-FileCopyrightText: 2026 ybblab
// SPDX-License-Identifier: Apache-2.0

package com.ybblab.jiumi.data

import android.annotation.SuppressLint
import android.content.Context
import android.provider.Settings
import com.ybblab.jiumi.probe.IProbeService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

internal data class ManagedNetworkApp(
    val pkg: String,
    val uid: Int,
    val installedAt: Long,
    val blocked: Boolean,
    val verifiedBoot: Int
) {
    val key: AppKey get() = AppKey(uid, pkg)
}

internal data class NetworkPolicy(
    val restoreEnabledAtBoot: Int? = null,
    val apps: Map<String, ManagedNetworkApp> = emptyMap(),
    val restoreFailures: Set<String> = emptySet(),
    val imported: Boolean = false
) {
    fun shouldRestore(app: ManagedNetworkApp, boot: Int): Boolean =
        restoreEnabledAtBoot?.let { it < boot && app.blocked && app.verifiedBoot < boot } == true

    fun encode(): String = JSONObject().put("restoreEnabledAtBoot", restoreEnabledAtBoot).put("imported", imported)
        .put("apps", JSONArray().apply {
            apps.values.forEach { app ->
                put(JSONObject().put("pkg", app.pkg).put("uid", app.uid).put("installedAt", app.installedAt)
                    .put("blocked", app.blocked).put("verifiedBoot", app.verifiedBoot))
            }
        }).toString()

    companion object {
        fun decode(text: String?): NetworkPolicy {
            val json = text?.let { runCatching { JSONObject(it) }.getOrNull() } ?: return NetworkPolicy()
            return NetworkPolicy(json.optInt("restoreEnabledAtBoot", -1).takeIf { it >= 0 },
                decodeApps(json.optJSONArray("apps") ?: JSONArray()), imported = json.optBoolean("imported"))
        }

        fun decodeApps(rows: JSONArray): Map<String, ManagedNetworkApp> = buildMap {
            for (index in 0 until rows.length()) {
                val row = rows.optJSONObject(index) ?: continue
                val pkg = row.optString("pkg")
                val uid = row.optInt("uid", -1)
                val installedAt = row.optLong("installedAt")
                val boot = row.optInt("verifiedBoot", -1)
                if (pkg.isNotEmpty() && uid >= 0 && installedAt > 0 && boot >= 0) {
                    put(pkg, ManagedNetworkApp(pkg, uid, installedAt, row.optBoolean("blocked"), boot))
                }
            }
        }
    }
}

/** Keeps the user's choices after Android discards its firewall rules at reboot. */
internal class NetworkManagement(
    context: Context,
    private val connectedProbe: () -> IProbeService?
) {
    private val prefs = context.getSharedPreferences("jiumi_settings", Context.MODE_PRIVATE)
    private val lock = Mutex()
    val boot: Int? = runCatching { Settings.Global.getInt(context.contentResolver, Settings.Global.BOOT_COUNT) }.getOrNull()
    private val policy = MutableStateFlow(NetworkPolicy.decode(prefs.getString(KEY, null)))
    val state = policy.asStateFlow()

    suspend fun setAutoRestore(enabled: Boolean): Boolean = transaction {
        val enabledAt = if (enabled) boot ?: return@transaction false else null
        val current = policy.value
        if (enabled == (current.restoreEnabledAtBoot != null)) return@transaction true
        save(current.copy(restoreEnabledAtBoot = enabledAt, restoreFailures = emptySet()))
    }

    /** Called for the per-app permission switch. A successful change also enrolls the app. */
    suspend fun change(key: AppKey, blocked: Boolean, expert: Boolean): JSONObject? = transaction {
        val service = connectedProbe() ?: return@transaction JSONObject().put("lock", "monitor")
        val result = call(service, key, if (blocked) "networkDeny" else "networkAllow", expert = expert)
            ?: return@transaction null
        val app = verifiedApp(key, blocked, result)
        if (app != null && !remember(app)) result.put("historyFailed", true)
        result
    }

    suspend fun add(key: AppKey, expert: Boolean): Boolean = transaction {
        val service = connectedProbe() ?: return@transaction false
        val result = call(service, key, "network", expert = expert) ?: return@transaction false
        val pkg = key.pkg ?: return@transaction false
        val installedAt = result.optLong("installedAt")
        val verifiedBoot = result.optInt("boot", -1)
        if (result.optString("lock").isNotEmpty() || installedAt <= 0 || verifiedBoot < 0 || !result.has("allowed")) {
            return@transaction false
        }
        val blocked = result.optBoolean("owned") && !result.optBoolean("allowed")
        remember(ManagedNetworkApp(pkg, key.uid, installedAt, blocked, verifiedBoot))
    }

    suspend fun setBlocked(app: ManagedNetworkApp, blocked: Boolean): Boolean = transaction {
        val current = policy.value.apps[app.pkg] ?: return@transaction false
        if (current.installedAt != app.installedAt || current.uid != app.uid) return@transaction false
        if (blocked) {
            val service = connectedProbe() ?: return@transaction false
            val updated = block(service, current) ?: return@transaction false
            remember(updated)
        } else {
            if (!release(current)) return@transaction false
            remember(current.copy(blocked = false))
        }
    }

    suspend fun remove(app: ManagedNetworkApp): Boolean = transaction {
        val current = policy.value
        val entry = current.apps[app.pkg] ?: return@transaction true
        if (entry.installedAt != app.installedAt || entry.uid != app.uid || !release(entry)) return@transaction false
        save(current.copy(apps = current.apps - entry.pkg, restoreFailures = current.restoreFailures - entry.pkg))
    }

    suspend fun onConnected(service: IProbeService) {
        transaction {
            val current = policy.value
            if (current.imported || connectedProbe() != service) return@transaction
            val existing = runCatching { JSONArray(service.ownedNetworkRules()) }.getOrNull() ?: return@transaction
            save(current.copy(apps = NetworkPolicy.decodeApps(existing) + current.apps, imported = true))
        }
        val currentBoot = boot ?: return
        // Each row is a separate transaction so manual changes and removals can take effect during restoration.
        for (pkg in policy.value.apps.keys) transaction {
            val current = policy.value
            val app = current.apps[pkg] ?: return@transaction
            if (!current.shouldRestore(app, currentBoot) || connectedProbe() != service) return@transaction
            val updated = block(service, app)
            if (updated == null || !remember(updated)) {
                policy.value = current.copy(restoreFailures = current.restoreFailures + pkg)
            }
        }
    }

    private fun block(service: IProbeService, app: ManagedNetworkApp): ManagedNetworkApp? =
        call(service, app.key, "networkDeny", app.installedAt)?.let { verifiedApp(app.key, true, it) }

    private fun release(app: ManagedNetworkApp): Boolean {
        if (!app.blocked) return true
        val service = connectedProbe() ?: return false
        val result = call(service, app.key, "networkRelease", app.installedAt) ?: return false
        return result.optBoolean("released") || result.optBoolean("stale")
    }

    private fun call(
        service: IProbeService, key: AppKey, action: String, installedAt: Long? = null, expert: Boolean = false
    ): JSONObject? {
        val pkg = key.pkg ?: return null
        return runCatching { JSONObject(service.appAccess(pkg, key.uid, action, installedAt?.toString().orEmpty(), expert)) }.getOrNull()
    }

    private fun verifiedApp(key: AppKey, blocked: Boolean, result: JSONObject): ManagedNetworkApp? {
        val pkg = key.pkg ?: return null
        val installedAt = result.optLong("installedAt")
        val verifiedBoot = result.optInt("boot", -1)
        if (installedAt <= 0 || verifiedBoot < 0 || result.optString("lock").isNotEmpty() || result.optBoolean("failed") ||
            !result.has("allowed") || result.optBoolean("allowed") == blocked || blocked && !result.optBoolean("owned")) return null
        return ManagedNetworkApp(pkg, key.uid, installedAt, blocked, verifiedBoot)
    }

    private fun remember(app: ManagedNetworkApp): Boolean {
        val current = policy.value
        return save(current.copy(apps = current.apps + (app.pkg to app), restoreFailures = current.restoreFailures - app.pkg))
    }

    @SuppressLint("UseKtx") // The KTX extension discards the result of commit().
    private fun save(next: NetworkPolicy): Boolean {
        if (next == policy.value) return true
        if (!prefs.edit().putString(KEY, next.encode()).commit()) return false
        policy.value = next
        return true
    }

    private suspend fun <T> transaction(change: () -> T): T = withContext(Dispatchers.IO) {
        lock.withLock { withContext(NonCancellable) { change() } }
    }

    private companion object {
        const val KEY = "network_management"
    }
}
