import os
import datetime
import logging
import urllib.request
import json
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger("CertificateManager")

def generate_key_and_csr(pc_name: str) -> tuple:
    """RSA 2048 anahtar çifti ve istemci adı içeren CSR oluşturur."""
    # 1. Özel Anahtar Üret (Private Key)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # 2. CSR Oluştur
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "TR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Tokat"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Merkez"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TOGU"),
        x509.NameAttribute(NameOID.COMMON_NAME, pc_name),
    ])
    
    csr_builder = x509.CertificateSigningRequestBuilder()
    csr_builder = csr_builder.subject_name(subject)
    csr = csr_builder.sign(private_key, hashes.SHA256())
    
    # 3. PEM formatına kodla
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    
    return private_key_pem, csr_pem

def save_private_key(path: str, key_pem: bytes) -> None:
    """Özel anahtarı diske yazar ve izinlerini 0o600 olarak sınırlar."""
    with open(path, "wb") as f:
        f.write(key_pem)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass

def get_ssl_context(certs_dir: str) -> "ssl.SSLContext":
    """CA sertifikası doğrulaması ve üretim ortamında hostname kontrolü ile SSL context döner."""
    import ssl
    import app_config as config
    ctx = ssl.create_default_context()
    ca_path = os.path.join(certs_dir, "ca.crt")
    
    is_prod = getattr(config, "PRODUCTION", False)
    if is_prod:
        if not os.path.exists(ca_path):
            raise FileNotFoundError("[GUVENLIK HATA] Uretim modunda SSL dogrulama icin ca.crt bulunmak zorundadir!")
        ctx.load_verify_locations(ca_path)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
    else:
        if os.path.exists(ca_path):
            ctx.load_verify_locations(ca_path)
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.check_hostname = False
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
    return ctx

def enroll_certificate(server_url: str, pc_name: str, token: str, certs_dir: str) -> bool:
    """Sunucu HTTPS API'sine bağlanıp yeni sertifika alır ve kaydeder."""
    try:
        os.makedirs(certs_dir, exist_ok=True)
        
        key_pem, csr_pem = generate_key_and_csr(pc_name)
        
        payload = {
            "pc_name": pc_name,
            "csr_pem": csr_pem.decode('utf-8'),
            "token": token
        }
        
        req_url = f"{server_url}/api/v1/enroll"
        req_data = json.dumps(payload).encode('utf-8')
        
        # GÜVENLİK TEMELİ: SSL context al
        ctx = get_ssl_context(certs_dir)
        
        req = urllib.request.Request(
            req_url,
            data=req_data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        
        with urllib.request.urlopen(req, context=ctx) as response:
            res_data = json.loads(response.read().decode('utf-8'))
            
        cert_pem = res_data["cert_pem"]
        ca_pem = res_data["ca_pem"]
        
        # Dosyaları diske yaz
        key_path = os.path.join(certs_dir, f"client_{pc_name}.key")
        cert_path = os.path.join(certs_dir, f"client_{pc_name}.crt")
        ca_path = os.path.join(certs_dir, "ca.crt")
        
        save_private_key(key_path, key_pem)
        with open(cert_path, "wb") as f:
            f.write(cert_pem.encode('utf-8'))
        with open(ca_path, "wb") as f:
            f.write(ca_pem.encode('utf-8'))
            
        logger.info(f"✅ Sertifikalar basariyla kaydoldu (Auto-Enrolled): client_{pc_name}.crt")
        return True
    except Exception as e:
        logger.error(f"❌ Sertifika kayit (Enrollment) basarisiz oldu: {e}")
        return False

def renew_certificate(server_url: str, pc_name: str, certs_dir: str) -> bool:
    """Mevcut aktif sertifikayı doğrulatarak yeni bir sertifika talep eder."""
    try:
        key_path = os.path.join(certs_dir, f"client_{pc_name}.key")
        cert_path = os.path.join(certs_dir, f"client_{pc_name}.crt")
        
        if not os.path.exists(key_path) or not os.path.exists(cert_path):
            logger.warning("Yenileme için mevcut sertifika bulunamadı. Yeniden enrollment baslatiliyor.")
            return False
            
        with open(cert_path, "r", encoding="utf-8") as f:
            current_cert_pem = f.read()
            
        # 1. Yeni Key ve yeni CSR üret (Perfect Forward Secrecy)
        new_key_pem, new_csr_pem = generate_key_and_csr(pc_name)
        
        payload = {
            "pc_name": pc_name,
            "current_cert_pem": current_cert_pem,
            "new_csr_pem": new_csr_pem.decode('utf-8')
        }
        
        req_url = f"{server_url}/api/v1/renew"
        req_data = json.dumps(payload).encode('utf-8')
        
        # GÜVENLİK TEMELİ: SSL context al
        ctx = get_ssl_context(certs_dir)
        
        req = urllib.request.Request(
            req_url,
            data=req_data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        
        with urllib.request.urlopen(req, context=ctx) as response:
            res_data = json.loads(response.read().decode('utf-8'))
            
        new_cert_pem = res_data["cert_pem"]
        new_ca_pem = res_data["ca_pem"]
        
        # Dosyaları güncelle (eski anahtar ve sertifikaların üzerine yaz)
        save_private_key(key_path, new_key_pem)
        with open(cert_path, "wb") as f:
            f.write(new_cert_pem.encode('utf-8'))
            
        logger.info(f"✅ Sertifika basariyla yenilendi (Auto-Renewed): client_{pc_name}.crt")
        return True
    except Exception as e:
        logger.error(f"❌ Sertifika yenileme (Renewal) basarisiz oldu: {e}")
        return False

def check_cert_expiry(certs_dir: str, pc_name: str, days_threshold: int = 30) -> bool:
    """Sertifikanın süresinin bitmesine days_threshold günden az kalıp kalmadığını kontrol eder.
    Yenileme gerekiyorsa True döner.
    """
    try:
        cert_path = os.path.join(certs_dir, f"client_{pc_name}.crt")
        if not os.path.exists(cert_path):
            return True  # Sertifika yoksa yenile/kaydol
            
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
            
        now = datetime.datetime.now(datetime.timezone.utc)
        not_valid_after = getattr(cert, "not_valid_after_utc", None)
        if not_valid_after is None:
            not_valid_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
            
        remaining_time = not_valid_after - now
        if remaining_time < datetime.timedelta(days=days_threshold):
            logger.info(f"Sertifika yenileme zamanı yaklaştı. Kalan süre: {remaining_time.days} gün.")
            return True
            
        return False
    except Exception as e:
        logger.error(f"Sertifika suresi kontrol edilirken hata: {e}")
        return True  # Hata durumunda tedbiren True dönerek yenileme tetiklensin
