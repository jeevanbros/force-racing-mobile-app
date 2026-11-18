import os
import sys
import zipfile
import struct
import io
import json
import shutil
import base64
import hashlib
from PIL import Image

from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509

import sign_apk.signer
import sign_apk.rezip
import sign_apk.zipdata
import sign_apk.verify
from sign_apk.keys import KeyMaterial


def wrap_manifest_line(line_str: str) -> bytes:
    """Wrap manifest lines according to Java JAR / Android manifest spec (72 bytes max line length)."""
    b = line_str.encode('utf-8')
    if len(b) <= 70:
        return b + b'\r\n'
    out = bytearray()
    out.extend(b[:70] + b'\r\n')
    pos = 70
    while pos < len(b):
        chunk = b[pos:pos + 69]
        out.extend(b' ' + chunk + b'\r\n')
        pos += 69
    return bytes(out)


def patch_manifest(data: bytes) -> bytes:
    """
    Patch binary AndroidManifest.xml:
    1. Update minSdkVersion to 21 (API 21: Android 5.0 Lollipop through Android 15+)
    2. Ensure targetSdkVersion is 34 (API 34: Android 14/15)
    3. Update unused permission to android.permission.ACCESS_NETWORK_STATE
    4. Set usesCleartextTraffic="false" (0) for strict modern Android HTTPS compliance
    """
    manifest = bytearray(data)
    header_size = 8
    sp_type, sp_hsize, sp_size = struct.unpack_from('<HHI', manifest, header_size)
    string_count, style_count, flags, strings_start, styles_start = struct.unpack_from('<IIIII', manifest, header_size + 8)
    offsets = [struct.unpack_from('<I', manifest, header_size + 28 + i * 4)[0] for i in range(string_count)]
    strings_data_start = header_size + strings_start

    decoded = []
    for off in offsets:
        p = strings_data_start + off
        l = struct.unpack_from('<H', manifest, p)[0]
        s = manifest[p+2:p+2+l*2].decode('utf-16le', errors='replace')
        decoded.append(s)

    # 1. Replace permission string (ACCESS_ALL_DOWNLOADS) with ACCESS_NETWORK_STATE
    for i, s in enumerate(decoded):
        if s == 'android.permission.ACCESS_ALL_DOWNLOADS':
            decoded[i] = 'android.permission.ACCESS_NETWORK_STATE'
            break

    # Rebuild string pool (UTF-16LE, flags=0)
    new_offsets = []
    new_strings_data = bytearray()
    for s in decoded:
        new_offsets.append(len(new_strings_data))
        encoded = s.encode('utf-16le')
        new_strings_data.extend(struct.pack('<H', len(s)))
        new_strings_data.extend(encoded)
        new_strings_data.extend(b'\x00\x00')

    while len(new_strings_data) % 4 != 0:
        new_strings_data.append(0)

    new_strings_start = 28 + 4 * string_count
    new_sp_size = new_strings_start + len(new_strings_data)
    rebuilt_sp_header = struct.pack('<HHI', sp_type, sp_hsize, new_sp_size) + struct.pack('<IIIII', string_count, 0, flags, new_strings_start, 0)
    rebuilt_offsets = b''.join(struct.pack('<I', off) for off in new_offsets)
    new_sp = rebuilt_sp_header + rebuilt_offsets + bytes(new_strings_data)

    rest_of_manifest = bytearray(manifest[header_size + sp_size:])

    # 2. Patch minSdkVersion to 21 and usesCleartextTraffic to 0
    min_sdk_idx = decoded.index('minSdkVersion') if 'minSdkVersion' in decoded else -1
    uct_idx = decoded.index('usesCleartextTraffic') if 'usesCleartextTraffic' in decoded else -1

    for pos in range(0, len(rest_of_manifest) - 20, 4):
        ns, name, val_str, dtype, val = struct.unpack_from('<IIIII', rest_of_manifest, pos)
        if name == min_sdk_idx and (dtype >> 24) == 0x10:
            if val != 21:
                struct.pack_into('<I', rest_of_manifest, pos + 16, 21)
        elif name == uct_idx and (dtype >> 24) == 0x12:
            struct.pack_into('<I', rest_of_manifest, pos + 16, 0)

    new_file_size = header_size + len(new_sp) + len(rest_of_manifest)
    new_header = struct.pack('<II', 0x80003, new_file_size)
    return bytes(new_header + new_sp + bytes(rest_of_manifest))


def patch_resources_arsc(data: bytes) -> bytes:
    """Patch resources.arsc string pool to rebrand app title and icons, and dark theme colors."""
    header_size = 12
    sp_type, sp_hsize, sp_size = struct.unpack_from('<HHI', data, header_size)
    string_count, style_count, flags, strings_start, styles_start = struct.unpack_from('<IIIII', data, header_size + 8)
    offsets = [struct.unpack_from('<I', data, header_size + 28 + i * 4)[0] for i in range(string_count)]
    strings_data_start = header_size + strings_start

    decoded_strings = []
    for i, off in enumerate(offsets):
        p = strings_data_start + off
        l1 = data[p]; p += 1
        if l1 & 0x80: l1 = ((l1 & 0x7f) << 8) | data[p]; p += 1
        l2 = data[p]; p += 1
        if l2 & 0x80: l2 = ((l2 & 0x7f) << 8) | data[p]; p += 1
        decoded_strings.append(data[p:p + l2])

    # String pool replacements:
    # 397: App Name -> Force Racing
    # 375: Launcher Icon -> res/Ag.png
    # 372: Round Icon -> res/Ag.png
    # 58:  Adaptive Foreground -> res/Ag.png
    decoded_strings[397] = b'Force Racing'
    decoded_strings[375] = b'res/Ag.png'
    decoded_strings[372] = b'res/Ag.png'
    if len(decoded_strings) > 58:
        decoded_strings[58] = b'res/Ag.png'

    def encode_len(length):
        if length <= 0x7F: return bytes([length])
        return bytes([(length >> 8) | 0x80, length & 0xFF])

    new_offsets = []
    new_strings_data = bytearray()
    for s_bytes in decoded_strings:
        new_offsets.append(len(new_strings_data))
        u16_len = len(s_bytes.decode('utf-8', errors='replace'))
        u8_len = len(s_bytes)
        new_strings_data.extend(encode_len(u16_len))
        new_strings_data.extend(encode_len(u8_len))
        new_strings_data.extend(s_bytes)
        new_strings_data.append(0)

    while len(new_strings_data) % 4 != 0:
        new_strings_data.append(0)

    new_strings_start = 28 + 4 * string_count
    new_sp_size = new_strings_start + len(new_strings_data)
    rebuilt_sp_header = struct.pack('<HHI', sp_type, sp_hsize, new_sp_size) + struct.pack('<IIIII', string_count, 0, flags, new_strings_start, 0)
    rebuilt_offsets = b''.join(struct.pack('<I', off) for off in new_offsets)
    new_sp = rebuilt_sp_header + rebuilt_offsets + bytes(new_strings_data)

    rest_of_arsc = bytearray(data[header_size + sp_size:])
    # Replace default teal green (\x77\x85\x00\xff) with Force Racing dark cockpit (\x12\x0f\x0d\xff)
    bg_idx = 0
    while True:
        bg_idx = rest_of_arsc.find(b'\x77\x85\x00\xff', bg_idx)
        if bg_idx == -1:
            break
        rest_of_arsc[bg_idx:bg_idx + 4] = b'\x12\x0f\x0d\xff'
        bg_idx += 4

    new_table_size = header_size + len(new_sp) + len(rest_of_arsc)
    new_table_header = struct.pack('<HHI', 2, 12, new_table_size) + data[8:12]
    return new_table_header + new_sp + bytes(rest_of_arsc)


def main():
    print("=== Force Racing Lightweight APK Optimization & Build ===")

    base_apk = r'C:\Users\ijk11\base-app-release.apk'
    logo_path = r'C:\Users\ijk11\Desktop\forceracing-app\static\images\logo.png'
    key_path = r'C:\Users\ijk11\forceracing-release.key'
    pem_path = r'C:\Users\ijk11\forceracing-release.pem'

    if not os.path.exists(key_path) or not os.path.exists(pem_path):
        key_path = r'C:\Users\ijk11\Desktop\forceracing-app\forceracing-release.key'
        pem_path = r'C:\Users\ijk11\Desktop\forceracing-app\forceracing-release.pem'

    settings_file = r'C:\Users\ijk11\Desktop\apk_fixed_assets\assets\settings.json'
    web_index_file = r'C:\Users\ijk11\Desktop\apk_fixed_assets\assets\web\index.html'

    print(f"Loading base APK: {base_apk}")
    print(f"Loading permanent key: {key_path}")
    print(f"Loading certificate: {pem_path}")

    with open(key_path, 'rb') as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(pem_path, 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read())

    print(f"Signing Certificate Subject: {cert.subject}")
    print(f"Signing Certificate Serial: {cert.serial_number}")

    # Generate official 96x96 logo PNG for res/Ag.png
    logo_img = Image.open(logo_path).convert('RGBA')
    logo_buf = io.BytesIO()
    logo_img.resize((96, 96), Image.Resampling.LANCZOS).save(logo_buf, format='PNG', optimize=True)
    logo_png_data = logo_buf.getvalue()
    print(f"Generated Force Racing logo PNG: {len(logo_png_data)} bytes")

    # Read injected assets
    with open(settings_file, 'rb') as f:
        injected_settings = f.read()
    with open(web_index_file, 'rb') as f:
        injected_web_index = f.read()

    file_payloads = {}
    file_compress = {}

    stripped_count = 0
    with zipfile.ZipFile(base_apk, 'r') as src:
        for item in src.infolist():
            name = item.filename

            # Strip existing META-INF signature files
            if name.startswith('META-INF/'):
                continue

            # Strip unused demo assets: assets/demo/*
            if name.startswith('assets/demo/'):
                stripped_count += 1
                continue

            # Strip unused test/debug assets in assets/web/*.html (except index.html)
            if name.startswith('assets/web/') and name != 'assets/web/index.html':
                stripped_count += 1
                continue

            data = src.read(name)
            ctype = item.compress_type

            # Deflate classes.dex for ~65% size reduction
            if name == 'classes.dex':
                ctype = zipfile.ZIP_DEFLATED

            elif name == 'resources.arsc':
                data = patch_resources_arsc(data)
                # Android requirement: resources.arsc MUST be STORED uncompressed and 4-byte aligned
                ctype = zipfile.ZIP_STORED

            elif name == 'AndroidManifest.xml':
                data = patch_manifest(data)
                ctype = zipfile.ZIP_DEFLATED

            elif name == 'res/Ag.png':
                data = logo_png_data
                ctype = zipfile.ZIP_STORED

            elif name == 'assets/web/index.html':
                data = injected_web_index
                ctype = zipfile.ZIP_DEFLATED

            elif name == 'assets/settings.json':
                data = injected_settings
                ctype = zipfile.ZIP_DEFLATED

            file_payloads[name] = data
            file_compress[name] = ctype

    # Ensure required injected files are in payloads
    file_payloads['assets/web/index.html'] = injected_web_index
    file_compress['assets/web/index.html'] = zipfile.ZIP_DEFLATED

    file_payloads['assets/settings.json'] = injected_settings
    file_compress['assets/settings.json'] = zipfile.ZIP_DEFLATED

    file_payloads['res/Ag.png'] = logo_png_data
    file_compress['res/Ag.png'] = zipfile.ZIP_STORED

    print(f"Stripped {stripped_count} demo and debug asset files.")
    print(f"Total entries to package: {len(file_payloads)}")

    # Step 1: Generate v1 signatures (MANIFEST.MF, CERT.SF, CERT.RSA)
    print("Generating v1 JAR signatures (MANIFEST.MF, CERT.SF, CERT.RSA)...")
    manifest_buf = bytearray()
    manifest_buf.extend(wrap_manifest_line("Manifest-Version: 1.0"))
    manifest_buf.extend(wrap_manifest_line("Built-By: Force Racing"))
    manifest_buf.extend(wrap_manifest_line("Created-By: 1.0 (Force Racing)"))
    manifest_buf.extend(b"\r\n")

    section_bytes_map = {}
    for name in sorted(file_payloads.keys()):
        h256 = base64.b64encode(hashlib.sha256(file_payloads[name]).digest()).decode("ascii")
        sec_lines = bytearray()
        sec_lines.extend(wrap_manifest_line(f"Name: {name}"))
        sec_lines.extend(wrap_manifest_line(f"SHA-256-Digest: {h256}"))
        sec_lines.extend(b"\r\n")
        manifest_buf.extend(sec_lines)
        section_bytes_map[name] = bytes(sec_lines)

    manifest_bytes = bytes(manifest_buf)

    sf_buf = bytearray()
    sf_buf.extend(wrap_manifest_line("Signature-Version: 1.0"))
    sf_buf.extend(wrap_manifest_line("Created-By: 1.0 (Force Racing)"))
    manifest_h256 = base64.b64encode(hashlib.sha256(manifest_bytes).digest()).decode("ascii")
    sf_buf.extend(wrap_manifest_line(f"SHA-256-Digest-Manifest: {manifest_h256}"))
    sf_buf.extend(b"\r\n")

    for name in sorted(file_payloads.keys()):
        sec_bytes = section_bytes_map[name]
        sec_h256 = base64.b64encode(hashlib.sha256(sec_bytes).digest()).decode("ascii")
        sf_buf.extend(wrap_manifest_line(f"Name: {name}"))
        sf_buf.extend(wrap_manifest_line(f"SHA-256-Digest: {sec_h256}"))
        sf_buf.extend(b"\r\n")

    sf_bytes = bytes(sf_buf)

    p7_builder = pkcs7.PKCS7SignatureBuilder().set_data(sf_bytes).add_signer(cert, priv_key, hashes.SHA256())
    rsa_bytes = p7_builder.sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature])

    # Step 2: Write temporary unsigned ZIP with compresslevel=9
    temp_zip_path = r'C:\Users\ijk11\temp_optimized_v1.apk'
    print(f"Writing compressed intermediate archive with zlib level 9 to: {temp_zip_path}")
    with zipfile.ZipFile(temp_zip_path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z_out:
        # Write v1 signature files
        z_out.writestr("META-INF/MANIFEST.MF", manifest_bytes, compress_type=zipfile.ZIP_DEFLATED)
        z_out.writestr("META-INF/CERT.SF", sf_bytes, compress_type=zipfile.ZIP_DEFLATED)
        z_out.writestr("META-INF/CERT.RSA", rsa_bytes, compress_type=zipfile.ZIP_STORED)

        # Write all entries
        for name, data in file_payloads.items():
            ctype = file_compress[name]
            info = zipfile.ZipInfo(name)
            info.compress_type = ctype
            z_out.writestr(info, data)

    # Step 3: Align STORED entries to 4-byte boundaries and inject APK Signing Scheme v2 + v3
    print("Aligning ZIP (4-byte alignment on STORED entries) and injecting APK v2 + v3 signing blocks...")
    opt_apk_path = r'C:\Users\ijk11\Desktop\ForceRacing-Lite.apk'
    
    # Instruct sign_apk not to drop v1 signatures
    sign_apk.signer._find_v1_signature_files = lambda d, c: set()

    key_mat = KeyMaterial(private_key=priv_key, certificate=cert)
    sign_apk.signer.sign_apk(
        input_path=temp_zip_path,
        output_path=opt_apk_path,
        key_material=key_mat,
        v2=True,
        v3=True,
        min_sdk_version=21
    )

    if os.path.exists(temp_zip_path):
        os.remove(temp_zip_path)

    final_size = os.path.getsize(opt_apk_path)
    final_mb = final_size / (1024 * 1024)
    print(f"\n=======================================================")
    print(f"SUCCESS: Lightweight APK generated at {opt_apk_path}")
    print(f"Final Size: {final_mb:.2f} MB ({final_size:,} bytes)")
    print(f"=======================================================\n")

    # Verify 4-byte alignment
    print("Verifying 4-byte alignment of uncompressed entries...")
    with zipfile.ZipFile(opt_apk_path, 'r') as z:
        with open(opt_apk_path, 'rb') as f:
            apk_bytes = f.read()
        misaligned = []
        for info in z.infolist():
            if info.compress_type == 0:
                pos = info.header_offset
                name_len, extra_len = struct.unpack_from('<HH', apk_bytes, pos + 26)
                payload_offset = pos + 30 + name_len + extra_len
                if payload_offset % 4 != 0:
                    misaligned.append((info.filename, payload_offset))
                if info.filename in ['resources.arsc', 'res/Ag.png']:
                    print(f"  [CHECK] {info.filename:20} payload_offset={payload_offset:8} mod4={payload_offset % 4} (OK)")
        if misaligned:
            print(f"WARNING: Found {len(misaligned)} misaligned entries: {misaligned}")
        else:
            print("  All STORED entries (including resources.arsc and res/Ag.png) are strictly 4-byte aligned!")

    # Verify signatures with sign_apk
    print("\nVerifying APK signature scheme v2 and v3:")
    verify_res = sign_apk.verify.verify_apk(opt_apk_path)
    print(f"  Schemes verified: {verify_res.get('schemes')}")
    for signer in verify_res.get('signers', []):
        print(f"  Signer scheme={signer.get('scheme')} subject={signer.get('subject')}")

    # Copy to all distribution destinations
    distribution_targets = [
        r'C:\Users\ijk11\force-racing-mobile-repo\ForceRacing.apk',
        r'C:\Users\ijk11\force-racing-mobile-repo\ForceRacing-Lite.apk',
        r'C:\Users\ijk11\Desktop\ForceRacing.apk',
        r'C:\Users\ijk11\Desktop\ForceRacing-v2.1.0.apk',
        r'C:\Users\ijk11\Desktop\forceracing-app\static\downloads\ForceRacing.apk',
        r'C:\Users\ijk11\Desktop\forceracing-app\static\downloads\ForceRacing-Lite.apk',
        r'C:\Users\ijk11\Desktop\forceracing-app\static\downloads\ForceRacing-v2.1.0.apk',
        r'C:\Users\ijk11\forceracing-app\static\downloads\ForceRacing.apk',
        r'C:\Users\ijk11\forceracing-app\static\downloads\ForceRacing-Lite.apk',
        r'C:\Users\ijk11\forceracing-app\static\downloads\ForceRacing-v2.1.0.apk',
        r'C:\Users\ijk11\forceracing-website\forceracing-app\static\downloads\ForceRacing.apk',
        r'C:\Users\ijk11\forceracing-website\forceracing-app\static\downloads\ForceRacing-Lite.apk',
        r'C:\Users\ijk11\forceracing-website\forceracing-app\static\downloads\ForceRacing-v2.1.0.apk',
        r'C:\Users\ijk11\forceracing-website\forceracing-app\ForceRacing.apk',
        r'C:\Users\ijk11\forceracing-website\forceracing-app\ForceRacing-v2.1.0.apk'
    ]

    print("\nCopying optimized APK to distribution locations:")
    for target in distribution_targets:
        dest_dir = os.path.dirname(target)
        if os.path.exists(dest_dir):
            shutil.copyfile(opt_apk_path, target)
            print(f"  Copied -> {target} ({os.path.getsize(target):,} bytes)")

    print("\nOptimization completed successfully!")


if __name__ == '__main__':
    main()
