# Proton VPN port forwarding patch

Based on LibreTorrent 4.1.1 (`ae96f20`). This patch adds **Network → Proton VPN port forwarding** and a live mapping status. It keeps libtorrent4j 2.1.0-38 so the project's Android compatibility is unchanged.

When enabled, LibreTorrent sends NAT-PMP mapping requests to `10.2.0.1:5351` over Android's active VPN network, requires the same external TCP and UDP port, renews the 60-second lease every 45 seconds, and updates the session's listening port when Proton returns a new one. Its ordinary UPnP and NAT-PMP mappers are disabled in this mode. On errors it retries every five seconds and reports the error under the setting. The status reports the NAT-PMP allocation and requested listening port; it does not prove that a remote peer can reach the device.

## Build

Use a machine with the Android SDK and Java/Gradle prerequisites specified by this repository. From the patched repository:

```sh
./gradlew :app:assembleBaseDebug
```

The APK is under `app/build/outputs/apk/base/debug/`. It is signed with a development key and uses the separate package name `org.proninyaroslav.libretorrent.debug`, so it can be installed alongside the official app. It has separate app data. A release build needs your own signing key.

## Cloud build from a phone

The patch includes `.github/workflows/build-proton-apk.yml`. On a GitHub repository containing the patched sources, a push to the default branch starts a GitHub Actions build and uploads `LibreTorrent-Proton-debug` as an artifact. In the repository on a phone browser, open **Actions → Build Proton test APK → latest run → Artifacts**, download the ZIP, extract the APK, and install it. The patched fork at https://github.com/coolplayerivan/libretorrent contains the source and build workflow.

## Device check

1. Generate a Proton P2P WireGuard profile with NAT-PMP enabled and import it into Android WireGuard. Do not share the profile's `PrivateKey`.
2. In Android VPN settings for WireGuard, enable **Always-on VPN** and **Block connections without VPN**. Ensure the profile routes IPv4 and IPv6 (`AllowedIPs = 0.0.0.0/0, ::/0`).
3. Start WireGuard, then enable **Network → Proton VPN port forwarding** in LibreTorrent. Check that the status shows a TCP/UDP port. Ordinary NAT-PMP and UPnP need no manual change; the new mode overrides them while enabled.
4. Reconnect WireGuard and check whether the status and LibreTorrent's listening port update. Confirm incoming reachability from another network. A successful NAT-PMP response alone cannot prove incoming connectivity.

GitHub Actions build 36062082176 completed successfully on 2026-09-24. The APK has not yet been exercised against an actual Proton tunnel on a phone. Proton's documented manual flow is at https://protonvpn.com/support/port-forwarding-manual-setup .
