package com.goteleport.vnet.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.util.Log
import com.goteleport.vnet.vnet.Host
import com.goteleport.vnet.vnet.NetworkConfig
import com.goteleport.vnet.vnet.Session
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

/**
 * Runs Teleport VNet over an Android VPN interface.
 *
 * The order of operations matters and is the opposite of the desktop clients.
 * There, VNet creates the TUN device itself and then edits the host's routing
 * table as it learns which ranges to claim. Android will not let an app change
 * a live interface, so the tunnel has to be fully specified before it exists.
 * The service therefore asks Go for the configuration VNet is going to want
 * ([com.goteleport.vnet.vnet.Client.planNetwork]), establishes the tunnel once,
 * and only then hands the descriptor to VNet.
 */
class TeleportVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.goteleport.vnet.android.START"
        const val ACTION_STOP = "com.goteleport.vnet.android.STOP"
        const val EXTRA_PROFILE = "profile"

        private const val CHANNEL_ID = "vnet"
        private const val NOTIFICATION_ID = 1

        /** Broadcast whenever the tunnel's state changes, so the UI can refresh. */
        const val ACTION_STATE_CHANGED = "com.goteleport.vnet.android.STATE_CHANGED"

        private val state = AtomicReference(State("stopped", null))

        fun state(): State = state.get()

        data class State(val status: String, val detail: String?)
    }

    // Written by the worker thread, read by whichever thread stops the service.
    @Volatile
    private var session: Session? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopTunnel("stopped by user")
                return START_NOT_STICKY
            }
        }

        val profile = intent?.getStringExtra(EXTRA_PROFILE)
        if (profile.isNullOrEmpty()) {
            Log.e(Teleport.TAG, "No profile supplied to VPN service")
            stopSelf()
            return START_NOT_STICKY
        }

        startForeground(NOTIFICATION_ID, buildNotification("Starting…"))
        publish("starting", null)

        thread(name = "vnet-runner") { run(profile) }
        // Not sticky: restarting after a process death would need the consent
        // dialog and a valid profile, both of which are the activity's job.
        return START_NOT_STICKY
    }

    private fun run(profile: String) {
        val client = Teleport.client(this)
        try {
            Log.i(Teleport.TAG, "Planning tunnel for profile $profile")
            val plan = client.planNetwork(profile)
            Log.i(
                Teleport.TAG,
                "Tunnel plan: address=${plan.addressIPv4}/${plan.prefixIPv4} " +
                    "routes=${plan.routes.lines()} dns=${plan.nameservers.lines()} " +
                    "zones=${plan.searchDomains.lines()}",
            )

            val descriptor = establish(plan)
                ?: throw IllegalStateException(
                    "VpnService.Builder.establish() returned null; VPN permission may have been revoked",
                )

            // detachFd, not getFd: Go closes the descriptor when the session
            // ends, so the ParcelFileDescriptor must not also own it.
            val fd = descriptor.detachFd()
            Log.i(Teleport.TAG, "Tunnel established, handing fd $fd to VNet")

            val running = client.startVNet(profile, fd.toLong(), VpnHost())
            session = running
            publish("connected", plan.searchDomains.replace("\n", ", "))
            updateNotification("Connected — ${plan.searchDomains.replace("\n", ", ")}")

            // Blocks until VNet exits, either because stopTunnel cancelled it or
            // because it failed.
            running.awaitExit()
            Log.i(Teleport.TAG, "VNet exited cleanly")
            publish("stopped", null)
        } catch (t: Throwable) {
            // gomobile turns a Go error into a thrown Exception, so this is the
            // single place every Go-side failure surfaces.
            Log.e(Teleport.TAG, "VNet failed", t)
            publish("failed", t.message ?: t.toString())
            updateNotification("Failed: ${t.message}")
        } finally {
            session = null
            client.stopVNet()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private fun establish(plan: NetworkConfig): android.os.ParcelFileDescriptor? {
        val builder = Builder()
            .setSession("Teleport VNet")
            .setMtu(1500)
            .addAddress(plan.addressIPv4, plan.prefixIPv4.toInt())

        for (route in plan.routes.lines().filter { it.isNotBlank() }) {
            val (address, prefix) = route.split("/", limit = 2).let {
                it[0] to (it.getOrNull(1)?.toIntOrNull() ?: 32)
            }
            builder.addRoute(address, prefix)
        }

        for (nameserver in plan.nameservers.lines().filter { it.isNotBlank() }) {
            builder.addDnsServer(nameserver)
        }

        // Android has no per-suffix DNS routing, so these do not scope which
        // queries reach VNet - every query does, and VNet forwards the ones it
        // does not own. They still help bare hostnames resolve.
        for (zone in plan.searchDomains.lines().filter { it.isNotBlank() }) {
            builder.addSearchDomain(zone)
        }

        // Keep this app outside its own tunnel. Only the Teleport CIDR range is
        // routed in, so VNet's connections to the proxy would not loop anyway,
        // but excluding ourselves makes that guarantee independent of what the
        // cluster configures as its range.
        try {
            builder.addDisallowedApplication(packageName)
        } catch (e: Exception) {
            Log.w(Teleport.TAG, "Could not exclude self from the tunnel", e)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }
        underlyingNetwork()?.let { builder.setUnderlyingNetworks(arrayOf(it)) }

        val configureIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        builder.setConfigureIntent(configureIntent)

        return builder.establish()
    }

    private fun stopTunnel(reason: String) {
        Log.i(Teleport.TAG, "Stopping tunnel: $reason")
        // Stop must not run on the main thread: it blocks until VNet's
        // goroutines have wound down.
        thread(name = "vnet-stop") {
            session?.stop()
            Teleport.client(this).stopVNet()
        }
    }

    override fun onRevoke() {
        // The user turned the VPN off from system settings, or another app took
        // over the VPN slot.
        Log.w(Teleport.TAG, "VPN permission revoked")
        publish("revoked", "Another VPN took over, or you disconnected from system settings")
        stopTunnel("revoked")
        super.onRevoke()
    }

    override fun onDestroy() {
        stopTunnel("service destroyed")
        super.onDestroy()
    }

    /**
     * Bridges VNet's host-configuration and nameserver seams to Android.
     *
     * Go calls these from its own goroutines, never on the main thread.
     */
    private inner class VpnHost : Host {
        override fun configureNetwork(cfg: NetworkConfig) {
            // The tunnel was already established from planNetwork, and Android
            // cannot change a live interface, so this is a check rather than an
            // action. VNet calls it about every ten seconds; a mismatch means
            // the cluster's config changed under us and the tunnel would have
            // to be rebuilt.
            Log.d(
                Teleport.TAG,
                "VNet host config: address=${cfg.addressIPv4} routes=${cfg.routes.lines()} " +
                    "dns=${cfg.nameservers.lines()} zones=${cfg.searchDomains.lines()}",
            )
        }

        override fun teardownNetwork() {
            Log.i(Teleport.TAG, "VNet asked to tear down the tunnel")
        }

        override fun upstreamNameservers(): String {
            val resolvers = underlyingResolvers()
            Log.d(Teleport.TAG, "Upstream nameservers: $resolvers")
            return resolvers.joinToString("\n")
        }
    }

    /** The device's real DNS servers, from a network that is not this VPN. */
    private fun underlyingResolvers(): List<String> {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = underlyingNetwork() ?: return emptyList()
        val properties = cm.getLinkProperties(network) ?: return emptyList()
        return properties.dnsServers.mapNotNull { address ->
            val literal = address.hostAddress ?: return@mapNotNull null
            // VNet expects host:port. IPv6 literals need brackets.
            if (literal.contains(":")) "[$literal]:53" else "$literal:53"
        }
    }

    /**
     * Picks a network that has internet access and is not a VPN, which is where
     * VNet's own traffic to the proxy goes and where upstream DNS lives.
     */
    private fun underlyingNetwork(): Network? {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        return cm.allNetworks.firstOrNull { network ->
            val caps = cm.getNetworkCapabilities(network) ?: return@firstOrNull false
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        }
    }

    private fun publish(status: String, detail: String?) {
        state.set(State(status, detail))
        sendBroadcast(Intent(ACTION_STATE_CHANGED).setPackage(packageName))
    }

    private fun buildNotification(text: String): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        if (manager.getNotificationChannel(CHANNEL_ID) == null) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "VNet", NotificationManager.IMPORTANCE_LOW),
            )
        }
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("Teleport VNet")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(open)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, buildNotification(text))
    }
}
