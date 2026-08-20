package com.goteleport.vnet.android

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.browser.customtabs.CustomTabsIntent
import androidx.core.content.ContextCompat
import com.goteleport.vnet.vnet.BrowserOpener
import kotlin.concurrent.thread

/**
 * The whole UI: point at a cluster, log in, turn the tunnel on, see which names
 * it will answer for.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var ui: MainView
    private val main = Handler(Looper.getMainLooper())

    private val vpnConsent = registerForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startTunnel()
        } else {
            ui.setStatus("VPN permission denied")
        }
    }

    private val notificationPermission = registerForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.RequestPermission(),
    ) { /* The tunnel runs either way; without it the notification is hidden. */ }

    private val stateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) = refresh()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        ui = MainView(this)
        setContentView(ui.root)

        ui.proxy.setText(Prefs.proxy(this))
        ui.user.setText(Prefs.user(this))
        ui.insecure.isChecked = Prefs.insecure(this)
        ui.debugLogs.isChecked = Prefs.debugLogs(this)

        ui.onCheckCluster = { checkCluster() }
        ui.onLoginHeadless = { login(headless = true) }
        ui.onLoginSSO = { login(headless = false) }
        ui.onConnect = { connect() }
        ui.onDisconnect = { disconnect() }
        ui.onListApps = { listApps() }
        ui.onLogout = { logout() }
        ui.onSettingsChanged = {
            Prefs.setInsecure(this, ui.insecure.isChecked)
            Prefs.setDebugLogs(this, ui.debugLogs.isChecked)
            Teleport.applySettings(this)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    override fun onStart() {
        super.onStart()
        ContextCompat.registerReceiver(
            this,
            stateReceiver,
            IntentFilter(TeleportVpnService.ACTION_STATE_CHANGED),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        refresh()
    }

    override fun onStop() {
        unregisterReceiver(stateReceiver)
        super.onStop()
    }

    private fun refresh() {
        val profile = Teleport.client(this).currentProfile()
        val state = TeleportVpnService.state()
        ui.setLoggedIn(profile.isNotEmpty())
        ui.setStatus(
            buildString {
                append("Tunnel: ").append(state.status)
                state.detail?.let { append("\n").append(it) }
                if (profile.isNotEmpty()) {
                    append("\n\nProfile: ").append(profile)
                    runCatching { Teleport.client(this@MainActivity).profileStatusText(profile) }
                        .onSuccess { append("\n").append(it) }
                        .onFailure { append("\n(could not read profile: ").append(it.message).append(")") }
                }
            },
        )
    }

    /** Runs work off the main thread; every Go call here can block on the network. */
    private fun background(label: String, work: () -> String) {
        ui.setBusy(true)
        ui.setStatus("$label…")
        thread(name = "ui-$label") {
            val message = try {
                work()
            } catch (t: Throwable) {
                Log.e(Teleport.TAG, "$label failed", t)
                "$label failed:\n${t.message ?: t.toString()}"
            }
            main.post {
                ui.setBusy(false)
                ui.setStatus(message)
                refresh()
            }
        }
    }

    private fun saveInputs() {
        Prefs.setProxy(this, ui.proxy.text.toString().trim())
        Prefs.setUser(this, ui.user.text.toString().trim())
    }

    private fun checkCluster() {
        saveInputs()
        val proxy = Prefs.proxy(this)
        if (proxy.isEmpty()) {
            ui.setStatus("Enter a proxy address first, for example teleport.example.com:443")
            return
        }
        background("Checking cluster") {
            val info = Teleport.client(this).pingProxy(proxy)
            buildString {
                append("Cluster: ").append(info.clusterName).append("\n")
                append("Proxy: ").append(info.proxyAddr).append("\n")
                append("Auth: ").append(info.authType)
                if (info.secondFactor.isNotEmpty()) append(" (2fa: ").append(info.secondFactor).append(")")
                append("\n")
                append("Headless login: ").append(if (info.headlessAllowed) "available" else "disabled").append("\n")
                val connectors = info.connectors.lines().filter { it.isNotBlank() }
                if (connectors.isEmpty()) {
                    append("SSO connectors: none")
                } else {
                    append("SSO connectors:\n")
                    connectors.forEach { line ->
                        val parts = line.split("|")
                        append("  ").append(parts.getOrElse(1) { parts[0] })
                            .append(" (").append(parts.getOrElse(0) { "" }).append(")\n")
                    }
                }
                if (!info.headlessAllowed && connectors.isEmpty()) {
                    append("\nNeither login method is available on this cluster. ")
                    append("Headless has to be enabled in the auth service config:\n")
                    append("  auth_service:\n    ...\n  # headless is on by default in recent versions")
                }
            }
        }
    }

    private fun login(headless: Boolean) {
        saveInputs()
        val proxy = Prefs.proxy(this)
        val user = Prefs.user(this)
        if (proxy.isEmpty()) {
            ui.setStatus("Enter a proxy address first")
            return
        }
        if (headless && user.isEmpty()) {
            ui.setStatus("Headless login needs your Teleport username")
            return
        }

        val opener = CustomTabOpener(this)
        background(if (headless) "Logging in (headless)" else "Logging in (SSO)") {
            val profile = if (headless) {
                Teleport.client(this).loginHeadless(proxy, user, opener)
            } else {
                Teleport.client(this).loginSSO(proxy, "", opener)
            }
            "Logged in to $profile"
        }
    }

    private fun connect() {
        val profile = Teleport.client(this).currentProfile()
        if (profile.isEmpty()) {
            ui.setStatus("Log in first")
            return
        }
        // Asks the user's consent the first time; returns null once granted.
        val consent = VpnService.prepare(this)
        if (consent != null) {
            vpnConsent.launch(consent)
        } else {
            startTunnel()
        }
    }

    private fun startTunnel() {
        val profile = Teleport.client(this).currentProfile()
        val intent = Intent(this, TeleportVpnService::class.java)
            .setAction(TeleportVpnService.ACTION_START)
            .putExtra(TeleportVpnService.EXTRA_PROFILE, profile)
        ContextCompat.startForegroundService(this, intent)
        ui.setStatus("Starting tunnel…")
    }

    private fun disconnect() {
        val intent = Intent(this, TeleportVpnService::class.java)
            .setAction(TeleportVpnService.ACTION_STOP)
        startService(intent)
        ui.setStatus("Stopping tunnel…")
    }

    private fun listApps() {
        val profile = Teleport.client(this).currentProfile()
        if (profile.isEmpty()) {
            ui.setStatus("Log in first")
            return
        }
        background("Listing apps") {
            val apps = Teleport.client(this).listTCPApps(profile).lines().filter { it.isNotBlank() }
            if (apps.isEmpty()) {
                "No TCP apps are visible to you in this cluster.\n\n" +
                    "VNet only proxies apps whose URI starts with tcp://; HTTP apps stay in the browser."
            } else {
                buildString {
                    append("TCP apps VNet will answer for:\n\n")
                    apps.forEach { line ->
                        val parts = line.split("\t")
                        append("  ").append(parts.getOrElse(1) { parts[0] }).append("\n")
                    }
                    append("\nWith the tunnel up, connect to any of these by name.")
                }
            }
        }
    }

    private fun logout() {
        val profile = Teleport.client(this).currentProfile()
        if (profile.isEmpty()) {
            ui.setStatus("Not logged in")
            return
        }
        background("Logging out") {
            Teleport.client(this).logout(profile)
            "Logged out of $profile"
        }
    }
}

/**
 * Opens login URLs in a Custom Tab.
 *
 * Chrome handles the whole authentication ceremony there, including a hardware
 * security key over USB or NFC and platform passkeys, so the app needs no
 * WebAuthn support of its own.
 *
 * Go calls this from a goroutine, so the launch is posted to the main thread.
 */
private class CustomTabOpener(private val activity: MainActivity) : BrowserOpener {
    override fun openURL(url: String) {
        Log.i(Teleport.TAG, "Opening login URL: $url")
        activity.runOnUiThread {
            try {
                CustomTabsIntent.Builder()
                    .setShowTitle(true)
                    .build()
                    .launchUrl(activity, Uri.parse(url))
            } catch (t: Throwable) {
                Log.e(Teleport.TAG, "Custom Tab failed, falling back to a browser intent", t)
                try {
                    activity.startActivity(
                        Intent(Intent.ACTION_VIEW, Uri.parse(url))
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                    )
                } catch (t2: Throwable) {
                    Toast.makeText(activity, "No browser available", Toast.LENGTH_LONG).show()
                }
            }
        }
    }
}
