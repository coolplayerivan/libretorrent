package org.proninyaroslav.libretorrent.core.model;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.util.Log;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.IntConsumer;

/** Proton's manual WireGuard port forwarding protocol, independent of libtorrent's router mapper. */
final class ProtonPortForwarder {
    private static final String TAG = "ProtonPortForwarder";
    private static final int LEASE_SECONDS = 60;
    private static final int RENEW_SECONDS = 45;
    private static final InetSocketAddress GATEWAY =
            new InetSocketAddress("10.2.0.1", 5351);

    private final ConnectivityManager connectivity;
    private final IntConsumer portChanged;
    private final ScheduledExecutorService worker = Executors.newSingleThreadScheduledExecutor();
    private volatile String status = "Waiting for VPN";
    private volatile boolean stopped;
    private int port;
    private Network lastNetwork;

    ProtonPortForwarder(Context context, IntConsumer portChanged) {
        connectivity = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        this.portChanged = portChanged;
    }

    String status() {
        return status;
    }

    void start() {
        worker.execute(this::renew);
    }

    void stop() {
        stopped = true;
        worker.shutdownNow();
        status = "Stopped";
    }

    private void renew() {
        if (stopped) return;
        int delay = 5;
        try {
            Network network = connectivity.getActiveNetwork();
            NetworkCapabilities capabilities = network == null ? null : connectivity.getNetworkCapabilities(network);
            if (capabilities == null || !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                port = 0;
                lastNetwork = null;
                status = "Waiting for VPN";
            } else {
                // The VPN network binds the UDP socket to the tunnel. Never query the Wi-Fi gateway.
                if (!network.equals(lastNetwork)) port = 0;
                int udp = request(network, 1);
                int tcp = request(network, 2);
                if (tcp != udp) throw new IOException("TCP and UDP received different ports");
                if (stopped) return;
                lastNetwork = network;
                status = "Mapped: " + tcp + " (TCP/UDP)";
                if (tcp != port) {
                    portChanged.accept(tcp);
                    port = tcp;
                }
                delay = RENEW_SECONDS;
            }
        } catch (Exception e) {
            status = "Mapping failed: " + e.getMessage();
            Log.w(TAG, status, e);
        } finally {
            if (!stopped) worker.schedule(this::renew, delay, TimeUnit.SECONDS);
        }
    }

    private static int request(Network network, int opcode) throws IOException {
        byte[] data = new byte[12];
        data[1] = (byte) opcode;
        // Proton's documented request uses private port 1 and assigned public port 0.
        data[5] = 1;
        data[11] = LEASE_SECONDS;
        InetAddress gateway = GATEWAY.getAddress();
        try (DatagramSocket socket = new DatagramSocket()) {
            network.bindSocket(socket);
            socket.setSoTimeout(1500);
            byte[] reply = new byte[32];
            DatagramPacket response = new DatagramPacket(reply, reply.length);
            for (int attempt = 0; attempt < 3; attempt++) {
                socket.send(new DatagramPacket(data, data.length, GATEWAY));
                try {
                    socket.receive(response);
                } catch (SocketTimeoutException e) {
                    if (attempt == 2) throw e;
                    continue;
                }
                if (!gateway.equals(response.getAddress()) || response.getPort() != 5351
                        || response.getLength() < 16 || reply[0] != 0 || (reply[1] & 255) != opcode + 128)
                    throw new IOException("Invalid NAT-PMP response");
                int result = unsigned16(reply, 2);
                int port = unsigned16(reply, 10);
                long lifetime = ((long) (reply[12] & 255) << 24) | ((long) (reply[13] & 255) << 16)
                        | ((long) (reply[14] & 255) << 8) | (reply[15] & 255);
                if (result != 0 || unsigned16(reply, 8) != 1 || port == 0 || lifetime < RENEW_SECONDS)
                    throw new IOException("NAT-PMP rejected mapping (code " + result + ")");
                return port;
            }
        }
        throw new IOException("NAT-PMP timed out");
    }

    private static int unsigned16(byte[] data, int offset) {
        return ((data[offset] & 255) << 8) | (data[offset + 1] & 255);
    }
}
