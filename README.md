# Force Racing Android Mobile Application

<div align="center">

[![Release](https://img.shields.io/github/v/release/jeevanbros/force-racing-mobile-app?style=for-the-badge&color=e5a93c)](https://github.com/jeevanbros/force-racing-mobile-app/releases/tag/v2.1.0)
[![App Size](https://img.shields.io/badge/App%20Size-3.01%20MB-success?style=for-the-badge&logo=android)](https://github.com/jeevanbros/force-racing-mobile-app/releases/download/v2.1.0/ForceRacing.apk)
[![Android Compatibility](https://img.shields.io/badge/Android-5.0%20(API%2021)%20%E2%86%92%2015%20(API%2035)-informational?style=for-the-badge&logo=android)](https://github.com/jeevanbros/force-racing-mobile-app)
[![Signature](https://img.shields.io/badge/Signature-v1%20%7C%20v2%20%7C%20v3%20Verified-blue?style=for-the-badge&logo=securityscorecard)](certs/)
[![License](https://img.shields.io/badge/License-Proprietary%20%2F%20Team%20KITS-red?style=for-the-badge)](LICENSE)

**Official high-performance mobile companion for the Force Racing Formula Student Team (KITS Warangal).**

[Direct Download (Standard APK)](#-direct-apk-downloads) • [Direct Download (Lite APK)](#-direct-apk-downloads) • [Features](#-core-features) • [Build Pipeline](#-build--optimization-pipeline) • [Security & Verification](#-cryptographic-signing--integrity)

</div>

---

## 🏎️ Overview

The **Force Racing Android App** delivers real-time telemetry, race statistics, event schedules, team announcements, and vehicle engineering specifications directly to Android smartphones and tablets. 

Engineered with an ultra-lean footprint of **only 3.01 MB**, the application marries a high-speed native shell with dynamic cloud-connected live telemetry, delivering instant load times and reliable offline fallbacks under harsh paddock and trackside conditions.

---

## 📥 Direct APK Downloads

Get the official, release-ready APK binaries directly from GitHub Releases:

| Package Variant | Binary Name | Size | Architecture | Direct Download Link |
| :--- | :--- | :--- | :--- | :--- |
| **Official Release (Production)** | `ForceRacing.apk` | **3.01 MB** (3,152,978 B) | Universal (`arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`) | [⬇️ Download ForceRacing.apk](https://github.com/jeevanbros/force-racing-mobile-app/releases/download/v2.1.0/ForceRacing.apk) |
| **Official Release (Lite Paddock)** | `ForceRacing-Lite.apk` | **3.01 MB** (3,152,978 B) | Universal (Low Data / Quick Launch) | [⬇️ Download ForceRacing-Lite.apk](https://github.com/jeevanbros/force-racing-mobile-app/releases/download/v2.1.0/ForceRacing-Lite.apk) |

> 🔗 **All Releases & Assets**: Explore release notes, cryptographic hashes, and historical versions on the [GitHub Releases Page](https://github.com/jeevanbros/force-racing-mobile-app/releases/tag/v2.1.0).

---

## ✨ Core Features

### 1. ⚡ Ultra-Lightweight 3.01 MB Footprint
- Streamlined binary assets with Deflate level 9 compression.
- Uncompressed assets 4-byte boundary aligned via `zipalign` for zero-overhead memory-mapped I/O (`mmap`).
- Installs in seconds, even over bandwidth-constrained trackside cellular connections.

### 2. 📱 Universal Android Compatibility (5.0 to 15)
- **Minimum SDK**: API 21 (Android 5.0 Lollipop)
- **Target SDK**: API 34 / 35 (Android 14 / Android 15 Vanilla Ice Cream)
- Backward and forward compatible with over 99.4% of active Android devices worldwide.

### 3. 🔄 Gesture-Driven Pull-to-Refresh
- Native Android `SwipeRefreshLayout` integration enables one-finger downward pull to sync live race timings, telemetry tables, and leaderboard updates.
- Micro-haptic feedback and smooth transition curves ensure a responsive mobile experience.

### 4. 🌓 System Dark/Light Theme Synchronization
- Automatically adapts to the host operating system's dark or light mode preference (`prefers-color-scheme`).
- Features a custom dark paddock mode with `#0b0d10` deep carbon background and `#e5a93c` Force Racing amber accents to conserve OLED battery life during race days.

### 5. 📡 Intelligent Offline Network Detection & Auto-Recovery
- Actively listens for device connectivity transitions using native network callbacks.
- Displays an unobtrusive offline notification bar when roaming into dead zones.
- Automatically retries and restores pending queries immediately upon network reconnection without app restarts.

### 6. ⏱️ Low-Latency UI & Race Telemetry Spinner
- Sub-100ms cold-start splash handoff with zero blank frames.
- Custom amber circular telemetry progress spinner keeps drivers and track engineers informed during data fetches.

---

## 🛠️ Repository Contents

```
force-racing-mobile-app/
├── ForceRacing.apk              # Production release APK (3.01 MB, dual-signed v1/v2/v3)
├── ForceRacing-Lite.apk         # Paddock Lite release APK (3.01 MB)
├── optimize_apk.py              # Advanced APK optimization, zipalign & signing pipeline
├── build_lite.py                # Standalone script for lightweight asset bundling
├── apk_fixed_assets/            # Extracted & patched binary assets
│   ├── assets/                  # Web app bundle, runtime configs (settings.json)
│   └── res_and_arsc/            # High-res adaptive icons (xxxhdpi) and resources.arsc
├── certs/                       # Public release signing certificates
│   ├── forceracing-release.pem  # X.509 PEM public certificate
│   └── forceracing_release.crt  # X.509 DER/CRT public certificate
├── .gitignore                   # Excludes private keystores, logs, and temp objects
└── README.md                    # Comprehensive documentation
```

---

## 🔒 Cryptographic Signing & Integrity

Every build artifact published in this repository is cryptographically signed using official Force Racing release keys. Both **APK Signature Scheme v2** (full file payload block) and **v3** (key rotation support), alongside **v1 (JAR signing)**, are injected.

### Public Certificate Specifications

| Field | Detail |
| :--- | :--- |
| **Common Name (CN)** | Force Racing |
| **Organization (O)** | Force Racing |
| **Organizational Unit (OU)** | Operations |
| **Locality (L)** | Warangal |
| **State (ST)** | Telangana |
| **Country (C)** | IN |
| **Certificate Serial** | `93457819644096656168522472365331985921` |
| **Validity** | November 2026 – November 2056 (30 Years) |

### Cryptographic Hashes (v2.1.0)

Verify the integrity of downloaded binaries prior to installation:

```text
File:   ForceRacing.apk
Size:   3,152,978 bytes (3.01 MB)
SHA256: F61F231A3B057D290F34F4B2B8F1DDB040BD5091099B6B0C89DE86D5C7D150D7

File:   ForceRacing-Lite.apk
Size:   3,152,978 bytes (3.01 MB)
SHA256: F61F231A3B057D290F34F4B2B8F1DDB040BD5091099B6B0C89DE86D5C7D150D7
```

### Verification Command

Using the Android SDK `apksigner`:
```bash
apksigner verify --verbose ForceRacing.apk
```
*Expected Output:*
```text
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Verified using v4 scheme: false
Number of signers: 1
```

---

## 🚀 Build & Optimization Pipeline

To reproduce or re-compile the optimized release APKs locally:

### Prerequisites
- Python 3.10+
- `cryptography`, `pillow`, `sign_apk` modules:
  ```bash
  pip install cryptography pillow sign_apk
  ```

### Re-running the Optimizer
```bash
python optimize_apk.py
```

The optimizer performs the following stages:
1. **Asset Parsing**: Inspects baseline APK and extracts binary XML, icons, and `resources.arsc`.
2. **String Pool Patching**: Customizes application package labels and theme colors in `resources.arsc`.
3. **High-Ratio Recompression**: Repacks all assets using Deflate level 9.
4. **4-Byte Alignment (`zipalign`)**: Aligns all `STORED` (uncompressed) stream entries on 4-byte boundaries for zero-copy memory mapping.
5. **Multi-Scheme Signing**: Generates SHA-256 digest manifests (`MANIFEST.MF`, `CERT.SF`), creates detached PKCS#7 signatures (`CERT.RSA`), and injects APK Signing Scheme v2/v3 blocks into the ZIP central directory prefix.

---

## 📲 Installation Guide

### Sideloading onto Android Devices:
1. Download `ForceRacing.apk` onto your Android phone or tablet from the [Download Link](https://github.com/jeevanbros/force-racing-mobile-app/releases/download/v2.1.0/ForceRacing.apk).
2. Tap the downloaded file in your browser or file manager.
3. If prompted with *"For your security, your phone is not allowed to install unknown apps from this source"*, tap **Settings** and toggle **Allow from this source**.
4. Tap **Install** and launch **Force Racing** from your home screen or app drawer.

---

## 🌐 Connected Ecosystem

- **Telemetry & Cloud Host**: [force-racing-revival.workers.dev](https://force-racing.force-racing-revival.workers.dev/)
- **Core Organization**: Force Racing Formula Student Team, KITS Warangal
- **Repository**: [https://github.com/jeevanbros/force-racing-mobile-app](https://github.com/jeevanbros/force-racing-mobile-app)

---

<div align="center">
<sub>Designed & Maintained for the Force Racing Formula Student Team • KITS Warangal</sub>
</div>
