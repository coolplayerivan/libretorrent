package org.proninyaroslav.libretorrent.core.model;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.util.Log;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Inet4Address;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;

/** Proton's manual WireGuard port forwarding protocol, independent of libtorrent's router mapper. */
final class ProtonPortForwarder {
    private static final String TAG = "ProtonPortForwarder";
    private static final int LEASE_SECONDS = 60;
    private static final int RENEW_SECONDS = 45;
    private static final InetSocketAddress GATEWAY =
            new InetSocketAddress("10.2.0.1", 5351);

    private final ConnectivityManager connectivity;
    private final BiConsumer<Integer, String> portChanged;
    private final ScheduledExecutorService worker = Executors.newSingleThreadScheduledExecutor();
    private volatile String status = "Waiting for VPN";
    private volatile boolean stopped;
    private int port;
    private Network lastNetwork;
    private String lastVpnAddress;

    ProtonPortForwarder(Context context, BiConsumer<Integer, String> portChanged) {
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
                lastVpnAddress = null;
                status = "Waiting for VPN";
            } else {
                // The VPN network binds the UDP socket to the tunnel. Never query the Wi-Fi gateway.
                if (!network.equals(lastNetwork)) port = 0;
                String vpnAddress = vpnAddress(network);
                String publicIp;
                try {
                    publicIp = publicAddress(network);
                } catch (IOException e) {
                    Log.w(TAG, "Could not read the NAT-PMP public address", e);
                    publicIp = "unknown";
                }
                int udp = request(network, 1);
                int tcp = request(network, 2);
                if (tcp != udp) throw new IOException("TCP and UDP received different ports");
                if (stopped) return;
                if (tcp != port || !network.equals(lastNetwork)
                        || !vpnAddress.equals(lastVpnAddress)) {
                    portChanged.accept(tcp, vpnAddress);
                    port = tcp;
                }
                lastNetwork = network;
                lastVpnAddress = vpnAddress;
                status = "Mapped: " + tcp + " (TCP/UDP); public IP: "
                        + publicIp + "; VPN: " + vpnAddress;
                delay = RENEW_SECONDS;
            }
        } catch (Exception e) {
            status = "Mapping failed: " + e.getMessage();
            Log.w(TAG, status, e);
        } finally {
            if (!stopped) worker.schedule(this::renew, delay, TimeUnit.SECONDS);
        }
    }

    private String vpnAddress(Network network) throws IOException {
        LinkProperties properties = connectivity.getLinkProperties(network);
        if (properties != null) {
            for (LinkAddress link : properties.getLinkAddresses()) {
                if (link.getAddress() instanceof Inet4Address)
                    return link.getAddress().getHostAddress();
            }
        }
        throw new IOException("VPN has no IPv4 address");
    }

    private static String publicAddress(Network network) throws IOException {
        byte[] data = new byte[2]; // NAT-PMP opcode 0 asks for the gateway's public IPv4.
        byte[] reply = new byte[32];
        try (DatagramSocket socket = new DatagramSocket()) {
            network.bindSocket(socket);
            socket.setSoTimeout(1500);
            DatagramPacket response = new DatagramPacket(reply, reply.length);
            for (int attempt = 0; attempt < 3; attempt++) {
                socket.send(new DatagramPacket(data, data.length, GATEWAY));
                try {
                    socket.receive(response);
                } catch (SocketTimeoutException e) {
                    if (attempt == 2) throw e;
                    continue;
                }
                if (!GATEWAY.getAddress().equals(response.getAddress())
                        || response.getPort() != 5351 || response.getLength() < 12
                        || reply[0] != 0 || (reply[1] & 255) != 128
                        || unsigned16(reply, 2) != 0)
                    throw new IOException("Invalid NAT-PMP public address response");
                return InetAddress.getByAddress(new byte[]{reply[8], reply[9], reply[10], reply[11]})
                        .getHostAddress();
            }
        }
        throw new IOException("NAT-PMP public address timed out");
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
