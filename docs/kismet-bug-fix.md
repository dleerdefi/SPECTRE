# Kismet SIGSEGV Bug Fix — `--no-plugins` Null Pointer Crash

## Summary

Kismet crashes with `SIGSEGV` (segmentation fault) when launched with the `--no-plugins` flag. This affects **all available versions** — the Kali packages and the upstream git repository.

SPECTRE uses `--no-plugins` in its Kismet survey provider, making this a blocking issue. The fix is a one-line null-pointer guard in `kismet_server.cc`.

## Affected Versions

| Version | Source | Status |
|---------|--------|--------|
| 2023.07.R2-0kali2 | `apt install kismet` (Kali) | Crashes |
| 2025.09.R1-0kali3 | `apt install kismet` (Kali) | Crashes |
| 2026.04.0-850df6844 | `git clone` (HEAD as of 2026-04-13) | Crashes |

## Root Cause

In `kismet_server.cc` (line ~993), `finalize_plugins()` is called **unconditionally** on a `plugintracker` shared pointer. When `--no-plugins` is passed, the `plugintracker` object is never created (lines 960–972), leaving it as a null `shared_ptr`. The call dereferences null and crashes.

**GDB backtrace:**

```
#0  plugin_tracker::finalize_plugins (this=0x0) at plugintracker.cc:447
#1  main () at kismet_server.cc:993
```

**Crash signature:**

```
SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x68}
```

The `si_addr=0x68` (offset 104) is the first struct member access inside `finalize_plugins()` through the null `this` pointer.

## The Fix

In `kismet_server.cc`, guard the `finalize_plugins()` call with a null check:

```diff
     // finalize any plugins which were waiting for other code to load
-    plugintracker->finalize_plugins();
+    if (plugintracker != nullptr)
+        plugintracker->finalize_plugins();
```

## Build from Source (with patch)

### 1. Install build dependencies

```bash
sudo DEBIAN_FRONTEND=noninteractive apt install -y \
  build-essential git libwebsockets-dev pkg-config zlib1g-dev \
  libnl-3-dev libnl-genl-3-dev libcap-dev libpcap-dev libnm-dev \
  libdw-dev libsqlite3-dev libsensors-dev libusb-1.0-0-dev \
  libprotobuf-c-dev protobuf-c-compiler librtlsdr-dev libmosquitto-dev
```

### 2. Clone, patch, and build

```bash
cd /tmp
git clone https://github.com/kismetwireless/kismet.git kismet-src
cd kismet-src

# Apply the fix
sed -i 's/^\(\s*\)plugintracker->finalize_plugins();/\1if (plugintracker != nullptr)\n\1    plugintracker->finalize_plugins();/' kismet_server.cc

# Build
./configure
make -j$(nproc)
sudo make suidinstall
```

### 3. Set up httpd credentials

Kismet requires HTTP credentials even in headless mode. Create them for the root user (since Kismet runs via `sudo`):

```bash
sudo mkdir -p /root/.kismet
echo -e "httpd_username=spectre\nhttpd_password=spectre" | \
  sudo tee /root/.kismet/kismet_httpd.conf > /dev/null
```

### 4. Verify

```bash
kismet --version
# Should output: Kismet 2026.xx.x-xxxxxxxxx

# Quick test (should run without crashing)
sudo kismet --silent --no-ncurses --no-plugins -c wlan0 &
sleep 10 && sudo kill %1
```

## Upstream Status — RESOLVED

- **Issue:** https://github.com/kismetwireless/kismet/issues/602
- **PR:** Merged by tranzmatt — "plugins: make sure plugintracker exists (fix #602)"
- **Fix:** Upstream adopted the null guard approach proposed in the issue
- **Kali:** The fix will be included in the next Kali Kismet package update. Until then, build from source using the instructions above.

## Notes

- The `--no-plugins` flag is intentional in SPECTRE — plugins add startup time and are not needed for passive survey
- Once Kali updates their Kismet package to include the upstream fix, the build-from-source workaround is no longer needed — `apt install kismet` will work directly
- The fix is safe — it simply skips plugin finalization when the tracker was never created
