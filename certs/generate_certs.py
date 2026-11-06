import os
import sys
import datetime
import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# common/config.py dosyasındaki ayarları okuyabilmek için import yolunu güncelle
certs_dir = os.path.dirname(os.path.abspath(__file__))
common_dir = os.path.join(os.path.dirname(certs_dir), "common")
if os.path.exists(common_dir) and common_dir not in sys.path:
    sys.path.insert(0, common_dir)

try:
    import app_config as config
    MQTT_BROKER = config.MQTT_BROKER
except ImportError:
    MQTT_BROKER = "localhost"


# Sertifikaların kaydedileceği klasör (Betiği çağıranın aktif dizini)
CERTS_DIR = os.getcwd()
os.makedirs(CERTS_DIR, exist_ok=True)

def get_local_ips():
    import socket
    ips = ["localhost", "127.0.0.1"]
    try:
        hostname = socket.gethostname()
        ips.append(hostname)
        for ip in socket.gethostbyname_ex(hostname)[2]:
            ips.append(ip)
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        main_ip = s.getsockname()[0]
        ips.append(main_ip)
        s.close()
    except Exception:
        pass
    return list(dict.fromkeys(ips))


def generate_key_and_cert(
    common_name: str,
    ca_key=None,
    ca_cert=None,
    is_ca: bool = False,
    ip_addresses=None
):
    """RSA 2048 anahtarı ve X.509 sertifikası üretir."""
    # 1. RSA Özel Anahtarı Oluştur
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # 2. Sertifika Sahibi ve Yayınlayan Bilgileri
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "TR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Tokat"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Merkez"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TOGU"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    if ca_cert:
        issuer = ca_cert.subject

    # 3. Geçerlilik Süresi (10 Yıl)
    now = datetime.datetime.now(datetime.timezone.utc)
    valid_from = now
    valid_to = now + datetime.timedelta(days=3650)

    # 4. Sertifika İnşası
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(private_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(valid_from)
    builder = builder.not_valid_after(valid_to)

    # Eklentiler (Extensions)
    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )
    else:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )

    # Broker/Sunucu için Subject Alternative Name (SAN) ekle
    if ip_addresses:
        san_list = []
        for addr in ip_addresses:
            try:
                ip = ipaddress.ip_address(addr)
                san_list.append(x509.IPAddress(ip))
            except ValueError:
                san_list.append(x509.DNSName(addr))
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False
        )

    # 5. Sertifikayı İmzala
    signing_key = private_key if is_ca else ca_key
    cert = builder.sign(signing_key, hashes.SHA256())

    return private_key, cert

def save_pem(filename_prefix: str, key, cert, target_dir: str = None):
    """Anahtar ve Sertifikayı PEM formatında diske kaydeder."""
    out_dir = target_dir or os.getcwd()
    os.makedirs(out_dir, exist_ok=True)
    key_path = os.path.join(out_dir, f"{filename_prefix}.key")
    cert_path = os.path.join(out_dir, f"{filename_prefix}.crt")

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"✅ Oluşturuldu: {os.path.join(out_dir, f'{filename_prefix}.key')} ve {os.path.join(out_dir, f'{filename_prefix}.crt')}")

def load_ca(target_dir: str = None):
    """Mevcut CA sertifikasını ve anahtarını certs/ klasöründen yükler."""
    src_dir = target_dir or os.getcwd()
    ca_key_path = os.path.join(src_dir, "ca.key")
    ca_cert_path = os.path.join(src_dir, "ca.crt")
    if os.path.exists(ca_key_path) and os.path.exists(ca_cert_path):
        try:
            with open(ca_key_path, "rb") as f:
                ca_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(ca_cert_path, "rb") as f:
                ca_cert = x509.load_pem_x509_certificate(f.read())
            return ca_key, ca_cert
        except Exception as e:
            print(f"⚠️ Mevcut CA yüklenirken hata oluştu: {e}")
            return None, None
    return None, None

def generate_default_certs(target_dir: str = None):
    print("🔐 X.509 Sertifika Üretim Sihirbazı\n")
    out_dir = target_dir or os.getcwd()
    os.makedirs(out_dir, exist_ok=True)
    
    # Mevcut CA'yi yüklemeyi dene
    ca_key, ca_cert = load_ca(target_dir=out_dir)
    
    if not ca_key or not ca_cert:
        print("🔐 Yeni Root CA üretiliyor...")
        ca_key, ca_cert = generate_key_and_cert("NocSentinelRootCA", is_ca=True)
        save_pem("ca", ca_key, ca_cert, target_dir=out_dir)
    else:
        print("🔐 Mevcut Root CA başarıyla yüklendi.")

    print(f"🔐 Varsayılan Sunucu ({MQTT_BROKER}) ve İstemci sertifikaları üretiliyor...")
    local_ips = get_local_ips()
    san_ips = list(dict.fromkeys(local_ips + [MQTT_BROKER]))
    server_key, server_cert = generate_key_and_cert(
        MQTT_BROKER,
        ca_key=ca_key,
        ca_cert=ca_cert,
        ip_addresses=san_ips
    )
    save_pem("server", server_key, server_cert, target_dir=out_dir)

    client_key, client_cert = generate_key_and_cert(
        "NocSentinelClient",
        ca_key=ca_key,
        ca_cert=ca_cert
    )
    save_pem("client", client_key, client_cert, target_dir=out_dir)
    print(f"\n🎉 İşlem tamamlandı. Sertifikalar '{out_dir}' klasörüne kaydedildi.")

def main():
    import sys
    args = sys.argv[1:]
    
    if not args:
        generate_default_certs()
    else:
        ca_key, ca_cert = load_ca()
        if not ca_key or not ca_cert:
            ca_key, ca_cert = generate_key_and_cert("NocSentinelRootCA", is_ca=True)
            save_pem("ca", ca_key, ca_cert)
            
        for client_name in args:
            print(f"\n🔐 '{client_name}' için benzersiz istemci sertifikası üretiliyor...")
            client_key, client_cert = generate_key_and_cert(
                client_name,
                ca_key=ca_key,
                ca_cert=ca_cert
            )
            save_pem(f"client_{client_name}", client_key, client_cert)

if __name__ == "__main__":
    main()
