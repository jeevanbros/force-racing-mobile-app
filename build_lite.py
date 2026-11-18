import os, zipfile, struct, io, json, shutil, base64, hashlib
from PIL import Image
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
import sign_apk.signer, sign_apk.rezip, sign_apk.zipdata
from sign_apk.keys import KeyMaterial

logo_path = r'C:\Users\ijk11\Desktop\forceracing-app\static\images\logo.png'
base_apk = r'C:\Users\ijk11\base-app-release.apk'
lite_unsigned = r'C:\Users\ijk11\lite_unsigned.apk'
lite_signed = r'C:\Users\ijk11\ForceRacing-Lite.apk'
key_file = r'C:\Users\ijk11\Desktop\forceracing-app\forceracing-release.key'
cert_file = r'C:\Users\ijk11\Desktop\forceracing-app\forceracing-release.pem'

with open(key_file, 'rb') as f:
    priv_key = serialization.load_pem_private_key(f.read(), password=None)
with open(cert_file, 'rb') as f:
    x509_cert = x509.load_pem_x509_certificate(f.read())

logo = Image.open(logo_path).convert('RGBA')
def get_png(w, h):
    buf = io.BytesIO()
    logo.resize((w, h), Image.Resampling.LANCZOS).save(buf, format='PNG')
    return buf.getvalue()

file_payloads = {}
file_compress = {}

redirect_html = (
    b'<!DOCTYPE html><html><head><meta charset="utf-8">'
    b'<meta name="viewport" content="width=device-width, initial-scale=1">'
    b'<title>Force Racing</title>'
    b'<meta http-equiv="refresh" content="0; url=https://force-racing.force-racing-revival.workers.dev/">'
    b'<style>body{background:#0b0d10;color:#fff;display:flex;flex-direction:column;justify-content:center;align-items:center;height:100vh;margin:0;font-family:sans-serif;}'
    b'.spinner{width:40px;height:40px;border:3px solid rgba(229,169,60,0.2);border-top-color:#e5a93c;border-radius:50%;animation:spin 0.8s linear infinite;margin-top:20px;}'
    b'@keyframes spin{to{transform:rotate(360deg);}}</style></head>'
    b'<body><img src="res/Ag.png" width="96" height="96" alt="Force Racing">'
    b'<div style="margin-top:16px;font-weight:700;letter-spacing:2px;">FORCE RACING</div>'
    b'<div class="spinner"></div>'
    b'<script>window.location.replace("https://force-racing.force-racing-revival.workers.dev/");'
    b'setTimeout(function(){window.location.href="https://force-racing.force-racing-revival.workers.dev/";},80);</script>'
    b'</body></html>'
)

with zipfile.ZipFile(base_apk, 'r') as src:
    for item in src.infolist():
        if item.filename.startswith('META-INF/') or item.filename.startswith('assets/demo/'):
            continue
        data = src.read(item.filename)
        ctype = item.compress_type

        # Compress classes.dex with DEFLATE for 65% size reduction
        if item.filename == 'classes.dex':
            ctype = zipfile.ZIP_DEFLATED

        elif item.filename == 'resources.arsc':
            header_size = 12
            sp_type, sp_hsize, sp_size = struct.unpack_from('<HHI', data, header_size)
            string_count, style_count, flags, strings_start, styles_start = struct.unpack_from('<IIIII', data, header_size + 8)
            offsets = [struct.unpack_from('<I', data, header_size + 28 + i*4)[0] for i in range(string_count)]
            strings_data_start = header_size + strings_start

            decoded_strings = []
            for i, off in enumerate(offsets):
                p = strings_data_start + off
                l1 = data[p]; p += 1
                if l1 & 0x80: l1 = ((l1 & 0x7f) << 8) | data[p]; p += 1
                l2 = data[p]; p += 1
                if l2 & 0x80: l2 = ((l2 & 0x7f) << 8) | data[p]; p += 1
                decoded_strings.append(data[p:p+l2])

            decoded_strings[397] = b'Force Racing'
            decoded_strings[372] = b'res/Ag.png'
            decoded_strings[375] = b'res/Ag.png'
            decoded_strings[58]  = b'res/Ag.png'

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
            bg_idx = rest_of_arsc.find(b'\x77\x85\x00\xff')
            if bg_idx != -1:
                rest_of_arsc[bg_idx:bg_idx+4] = b'\xff\xff\xff\xff'

            new_table_size = header_size + len(new_sp) + len(rest_of_arsc)
            new_table_header = struct.pack('<HHI', 2, 12, new_table_size) + data[8:12]
            data = new_table_header + new_sp + bytes(rest_of_arsc)
            ctype = zipfile.ZIP_STORED

        elif item.filename == 'AndroidManifest.xml':
            manifest = bytearray(data)
            val = struct.unpack_from('<I', manifest, 5296)[0]
            if val == 31:
                struct.pack_into('<I', manifest, 5296, 24)
            data = bytes(manifest)

        elif item.filename.startswith('assets/web/'):
            data = redirect_html

        elif item.filename == 'assets/settings.json':
            cfg = {
                'sites': [{'url': 'https://force-racing.force-racing-revival.workers.dev/', 'title': 'Force Racing'}],
                'other': 'https://force-racing.force-racing-revival.workers.dev/',
                'match': [
                    ['host', 'endsWith', 'workers.dev'],
                    ['host', 'endsWith', 'forceracing.in'],
                    ['host', 'equals', 'localhost'],
                    ['host', 'startsWith', '192.168.']
                ],
                'local_sites': False, 'remote_debug': False, 'console_log': False,
                'js_interface': False, 'context_menu': False, 'not_matching': False,
                'web_settings': {'JavaScriptEnabled': True}, 'source': 'assets'
            }
            data = json.dumps(cfg, indent=2).encode('utf-8')

        elif item.filename in ['res/Ag.png', 'res/p8.png', 'res/2d.png', 'res/s4.png', 'res/W5.png']:
            data = get_png(144, 144)
            ctype = zipfile.ZIP_STORED
        elif item.filename == 'res/Z8.png':
            data = get_png(132, 66)
            ctype = zipfile.ZIP_STORED

        file_payloads[item.filename] = data
        file_compress[item.filename] = ctype

# Generate v1 signature
manifest_lines = ['Manifest-Version: 1.0', 'Built-By: Force Racing', 'Created-By: 1.0 (Force Racing)', '']
entry_chunks = {}
for name in sorted(file_payloads.keys()):
    sha = base64.b64encode(hashlib.sha256(file_payloads[name]).digest()).decode('ascii')
    chunk = f'Name: {name}\r\nSHA-256-Digest: {sha}\r\n\r\n'
    entry_chunks[name] = chunk
    manifest_lines.append(f'Name: {name}')
    manifest_lines.append(f'SHA-256-Digest: {sha}')
    manifest_lines.append('')
manifest_bytes = '\r\n'.join(manifest_lines).encode('utf-8')

mf_digest_str = base64.b64encode(hashlib.sha256(manifest_bytes).digest()).decode('ascii')
sf_lines = [
    'Signature-Version: 1.0',
    'Created-By: 1.0 (Force Racing)',
    f'SHA-256-Digest-Manifest: {mf_digest_str}',
    ''
]
for name in sorted(file_payloads.keys()):
    chunk_bytes = entry_chunks[name].encode('utf-8')
    chunk_digest = base64.b64encode(hashlib.sha256(chunk_bytes).digest()).decode('ascii')
    sf_lines.append(f'Name: {name}')
    sf_lines.append(f'SHA-256-Digest: {chunk_digest}')
    sf_lines.append('')
sf_bytes = '\r\n'.join(sf_lines).encode('utf-8')

builder = pkcs7.PKCS7SignatureBuilder().set_data(sf_bytes).add_signer(x509_cert, priv_key, hashes.SHA256())
rsa_bytes = builder.sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature])

with zipfile.ZipFile(lite_unsigned, 'w') as dst:
    for v1_name, v1_data in [('META-INF/MANIFEST.MF', manifest_bytes), ('META-INF/CERT.SF', sf_bytes), ('META-INF/CERT.RSA', rsa_bytes)]:
        info = zipfile.ZipInfo(v1_name)
        info.compress_type = zipfile.ZIP_DEFLATED
        dst.writestr(info, v1_data)
    for name in file_payloads:
        info = zipfile.ZipInfo(name)
        info.compress_type = file_compress[name]
        dst.writestr(info, file_payloads[name])

sign_apk.signer._find_v1_signature_files = lambda d, c: set()
key_mat = KeyMaterial(private_key=priv_key, certificate=x509_cert)
sign_apk.signer.sign_apk(
    input_path=lite_unsigned,
    output_path=lite_signed,
    key_material=key_mat,
    v2=True,
    v3=True,
    min_sdk_version=24
)

size_mb = os.path.getsize(lite_signed) / (1024*1024)
print(f'SUCCESS: ForceRacing-Lite.apk generated! Size: {size_mb:.2f} MB ({os.path.getsize(lite_signed):,} bytes)')

# Copy to all distribution paths
targets = [
    r'C:\Users\ijk11\Desktop\ForceRacing.apk',
    r'C:\Users\ijk11\Desktop\ForceRacing-v2.1.0.apk',
    r'C:\Users\ijk11\Desktop\forceracing-app\static\downloads\ForceRacing.apk',
    r'C:\Users\ijk11\Desktop\forceracing-app\static\downloads\ForceRacing-Lite.apk',
    r'C:\Users\ijk11\Desktop\forceracing-app\static\downloads\ForceRacing-v2.1.0.apk',
    r'C:\Users\ijk11\forceracing-app\static\downloads\ForceRacing.apk',
    r'C:\Users\ijk11\forceracing-app\static\downloads\ForceRacing-Lite.apk',
    r'C:\Users\ijk11\forceracing-app\static\downloads\ForceRacing-v2.1.0.apk',
]
for t in targets:
    shutil.copyfile(lite_signed, t)
    print(f'Copied to {t}')
