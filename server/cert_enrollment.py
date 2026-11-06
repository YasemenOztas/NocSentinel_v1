import os
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
import logging

logger = logging.getLogger("CertEnrollment")

import sys

# Resolve certs directory absolute path
SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
import path_helper

CERTS_DIR = path_helper.get_persistent_dir("certs")
def load_ca():
    """Mevcut CA sertifikasını ve anahtarını certs/ klasöründen yükler."""
    ca_key_path = os.path.join(CERTS_DIR, "ca.key")
    ca_cert_path = os.path.join(CERTS_DIR, "ca.crt")
    
    if not os.path.exists(ca_key_path) or not os.path.exists(ca_cert_path):
        raise FileNotFoundError(f"Root CA bulunamadi! Yol: {ca_key_path} veya {ca_cert_path}")
        
    # GÜVENLİK SERTLEŞTİRMESİ: CA key dosyasının disk izinlerini 0o600 olarak sıkılaştır
    try:
        os.chmod(ca_key_path, 0o600)
    except Exception as perm_err:
        logger.warning(f"CA key izinleri sikilastirilamadi (Windows ACL veya yetki sorunu): {perm_err}")
        
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
        
    return ca_key, ca_cert

def get_cert_fingerprint(cert: x509.Certificate) -> str:
    """Sertifikanın SHA-256 fingerprint (parmak izi) değerini hex olarak döner."""
    return cert.fingerprint(hashes.SHA256()).hex()

def sign_csr(csr_pem: str, expected_cn: str, expires_days: int = 365) -> tuple:
    """İstemciden gelen CSR PEM verisini doğrular ve CA ile imzalar.
    Dönen değerler: (cert_pem_str, serial_number_str, fingerprint_str, expires_at_datetime)
    """
    ca_key, ca_cert = load_ca()
    
    # CSR yükle
    csr = x509.load_pem_x509_csr(csr_pem.encode('utf-8'))
    
    # Common Name (CN) kontrolü
    cn_attributes = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cn_attributes:
        raise ValueError("CSR icerisinde Common Name (CN) bulunamadi.")
        
    actual_cn = cn_attributes[0].value
    if actual_cn != expected_cn:
        raise ValueError(f"CSR Common Name ('{actual_cn}') ile beklenen istemci adi ('{expected_cn}') eslesmiyor.")
        
    # Sertifika oluştur
    now = datetime.datetime.now(datetime.timezone.utc)
    valid_from = now
    valid_to = now + datetime.timedelta(days=expires_days)
    
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.public_key(csr.public_key())
    
    serial_number = x509.random_serial_number()
    builder = builder.serial_number(serial_number)
    builder = builder.not_valid_before(valid_from)
    builder = builder.not_valid_after(valid_to)
    
    # Basic constraints (client certificate)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    )
    
    # İmzala
    cert = builder.sign(ca_key, hashes.SHA256())
    
    # PEM formatına çevir
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    fingerprint = get_cert_fingerprint(cert)
    
    return cert_pem, str(serial_number), fingerprint, valid_to

def generate_crl_pem(serials: list) -> str:
    """İptal edilen seri numaralarına ait standart X.509 CRL PEM verisi üretir."""
    ca_key, ca_cert = load_ca()
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = builder.last_update(now)
    builder = builder.next_update(now + datetime.timedelta(days=30))
    
    for serial_str in serials:
        try:
            serial_num = int(serial_str)
            revoked_cert = x509.RevokedCertificateBuilder()\
                .serial_number(serial_num)\
                .revocation_date(now)\
                .build()
            builder = builder.add_revoked_certificate(revoked_cert)
        except ValueError:
            continue
            
    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.PEM).decode('utf-8')

def update_crl_file(db_session) -> None:
    """Veritabanındaki aktif olmayan/iptal edilmiş sertifikaları okur ve ca.crl dosyasını günceller."""
    try:
        from database import IstemciSertifikasi
        revoked_certs = db_session.query(IstemciSertifikasi).filter(IstemciSertifikasi.status.in_(["REVOKED", "EXPIRED"])).all()
        serials = [c.serial_number for c in revoked_certs]
        
        crl_pem = generate_crl_pem(serials)
        crl_path = os.path.join(CERTS_DIR, "ca.crl")
        
        with open(crl_path, "w", encoding="utf-8") as f:
            f.write(crl_pem)
            
        # CRL dosyasının da izinlerini kısıtla
        try:
            os.chmod(crl_path, 0o600)
        except Exception:
            pass
            
        logger.info(f"[CRL] Standart X.509 CRL iptal listesi guncellendi: {crl_path} ({len(serials)} adet sertifika listelendi)")
    except Exception as e:
        logger.error(f"[CRL] CRL dosyası olusturulurken/guncellenirken hata: {e}")
