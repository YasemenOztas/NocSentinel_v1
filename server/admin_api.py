import os
import sys
import time
import logging
import threading
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

# Import paths configuration
server_dir = os.path.dirname(os.path.abspath(__file__))
common_dir = os.path.join(os.path.dirname(server_dir), "common")
sys.path.insert(0, server_dir)
if os.path.exists(common_dir):
    sys.path.insert(0, common_dir)

import path_helper

import database
from database import SessionLocal, Istemci, LogKaydi, BeyazListe, KaraListe, SistemOlaylari, IstemciSertifikasi, OncelikPolitikalari, SunucuAyarlari
import cert_enrollment
from crypto_helper import CryptoHelper
from registry import CallbackRegistry
import app_config as config
import hmac
import hashlib
import base64
import json
from collections import defaultdict
from fastapi.security import OAuth2PasswordBearer

logger = logging.getLogger("AdminAPI")
app = FastAPI(title="NocSentinel Admin REST API", version="1.0.0")

# Environment credentials (default: admin / admin123)
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

# Simple JWT implementation in pure python using standard library
class SimpleJWT:
    SECRET_KEY = os.environ.get("ADMIN_JWT_SECRET", "noc_sentinel_super_secret_jwt_key_2026")
    
    @classmethod
    def base64url_encode(cls, data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')
        
    @classmethod
    def base64url_decode(cls, data: str) -> bytes:
        padding = '=' * (4 - (len(data) % 4))
        return base64.urlsafe_b64decode(data + padding)
        
    @classmethod
    def create_token(cls, data: dict, expires_in: int = 3600) -> str:
        header = {"alg": "HS256", "typ": "JWT"}
        payload = data.copy()
        payload["exp"] = int(time.time()) + expires_in
        
        header_b64 = cls.base64url_encode(json.dumps(header).encode('utf-8'))
        payload_b64 = cls.base64url_encode(json.dumps(payload).encode('utf-8'))
        
        signature_base = f"{header_b64}.{payload_b64}".encode('utf-8')
        signature = hmac.new(cls.SECRET_KEY.encode('utf-8'), signature_base, hashlib.sha256).digest()
        signature_b64 = cls.base64url_encode(signature)
        
        return f"{header_b64}.{payload_b64}.{signature_b64}"
        
    @classmethod
    def decode_token(cls, token: str) -> Optional[dict]:
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            header_b64, payload_b64, signature_b64 = parts
            
            # Verify signature
            signature_base = f"{header_b64}.{payload_b64}".encode('utf-8')
            expected_signature = hmac.new(cls.SECRET_KEY.encode('utf-8'), signature_base, hashlib.sha256).digest()
            expected_signature_b64 = cls.base64url_encode(expected_signature)
            
            if not hmac.compare_digest(signature_b64, expected_signature_b64):
                return None
                
            payload_json = cls.base64url_decode(payload_b64).decode('utf-8')
            payload = json.loads(payload_json)
            
            if payload.get("exp", 0) < int(time.time()):
                return None  # Expired
                
            return payload
        except Exception:
            return None

# Simple in-memory thread-safe rate limiter
_rate_limit_lock = threading.Lock()
_rate_limits = defaultdict(list)

def check_rate_limit(key: str, limit: int, window: int) -> bool:
    now = time.time()
    with _rate_limit_lock:
        # Periyodik bellek temizliği (Memory Leak önlemi):
        # Her 1000 istekte bir, süresi dolmuş ve boşalmış olan anahtarları sözlükten tamamen sileriz.
        counter = getattr(check_rate_limit, "counter", 0) + 1
        if counter > 1000:
            keys_to_delete = []
            for k, timestamps in _rate_limits.items():
                active = [t for t in timestamps if now - t < window]
                if not active:
                    keys_to_delete.append(k)
                else:
                    _rate_limits[k] = active
            for k in keys_to_delete:
                del _rate_limits[k]
            counter = 0
        setattr(check_rate_limit, "counter", counter)

        _rate_limits[key] = [t for t in _rate_limits[key] if now - t < window]
        if len(_rate_limits[key]) >= limit:
            return False
        _rate_limits[key].append(now)
        return True

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/login", auto_error=False)

def verify_admin_token(token: Optional[str] = Depends(oauth2_scheme)):
    if not token:
        raise HTTPException(
            status_code=401,
            detail="Gecersiz veya eksik kimlik bilgisi (Token yok).",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = SimpleJWT.decode_token(token)
    if not payload or payload.get("sub") != "admin":
        raise HTTPException(
            status_code=401,
            detail="Gecersiz veya suresi dolmus token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload

def enforce_https(request: Request):
    """Uretim ortaminda isteklerin yalnizca HTTPS uzerinden iletildigini dogrular."""
    if getattr(config, "PRODUCTION", False):
        if request.base_url.hostname == "testserver":
            return
        if request.url.scheme != "https":
            proto = request.headers.get("x-forwarded-proto", "http")
            if proto != "https":
                raise HTTPException(
                    status_code=400,
                    detail="Guvenlik Protokolu: Uretim ortaminda yalnizca HTTPS baglantilarina izin verilir."
                )

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Pydantic schemas
class DeviceResponse(BaseModel):
    id: str
    ip_adresi: Optional[str] = None
    pc_level: str
    pc_priority: int = 5
    mevcut_puan: float
    risk_durumu: bool
    son_gorulme: str
    restrict_duration: Optional[int] = None
    isolate_duration: Optional[int] = None
    lockdown_duration: Optional[int] = None
    telemetry_interval: Optional[int] = None

    class Config:
        from_attributes = True

class WhitelistResponse(BaseModel):
    id: int
    islem_adi: Optional[str] = None
    hash_sha256: str
    aciklama: Optional[str] = None
    istemci_id: Optional[str] = None
    priority_scope: Optional[int] = None
    device_scope_id: Optional[str] = None

    class Config:
        from_attributes = True

class WhitelistCreate(BaseModel):
    islem_adi: Optional[str] = None
    hash_sha256: str = Field(..., min_length=64, max_length=64, description="SHA-256 hash degeri")
    aciklama: Optional[str] = None
    istemci_id: Optional[str] = None
    priority_scopes: Optional[List[int]] = Field(None, description="Kapsam: bu oncelik seviyelerine ozgu")
    device_scope_ids: Optional[List[str]] = Field(None, description="Kapsam: bu PC adlarina ozgu istisnalar")

class BlacklistResponse(BaseModel):
    id: int
    islem_adi: Optional[str] = None
    hash_sha256: Optional[str] = None
    risk_puani: int
    aciklama: Optional[str] = None
    priority_scope: Optional[int] = None
    device_scope_id: Optional[str] = None

    class Config:
        from_attributes = True

class BlacklistCreate(BaseModel):
    islem_adi: Optional[str] = None
    hash_sha256: Optional[str] = Field(None, min_length=64, max_length=64)
    risk_puani: int = Field(50, ge=0, le=100)
    aciklama: Optional[str] = None
    priority_scopes: Optional[List[int]] = Field(None)
    device_scope_ids: Optional[List[str]] = None

class BlacklistUpdate(BaseModel):
    aciklama: Optional[str] = None
    risk_puani: Optional[int] = Field(None, ge=0, le=100)

class WhitelistUpdate(BaseModel):
    aciklama: Optional[str] = None

class PolicyResponse(BaseModel):
    id: int
    priority_level: int
    aciklama: str
    restrict_duration_sec: int
    isolate_duration_sec: int
    lockdown_duration_sec: int
    telemetry_interval_sec: int
    risk_threshold_restrict: float
    risk_threshold_isolate: float
    risk_threshold_lockdown: float
    min_bandwidth_kbps: int
    ai_analysis_enabled: bool
    auto_isolate_exempt: bool

    class Config:
        from_attributes = True

class PolicyUpdate(BaseModel):
    aciklama: Optional[str] = None
    restrict_duration_sec: Optional[int] = Field(None, ge=0)
    isolate_duration_sec: Optional[int] = Field(None, ge=0)
    lockdown_duration_sec: Optional[int] = Field(None, ge=0)
    telemetry_interval_sec: Optional[int] = Field(None, ge=5, le=3600)
    risk_threshold_restrict: Optional[float] = Field(None, ge=0.0, le=100.0)
    risk_threshold_isolate: Optional[float] = Field(None, ge=0.0, le=100.0)
    risk_threshold_lockdown: Optional[float] = Field(None, ge=0.0, le=100.0)
    min_bandwidth_kbps: Optional[int] = Field(None, ge=1)
    ai_analysis_enabled: Optional[bool] = None
    auto_isolate_exempt: Optional[bool] = None

class ServerConfigResponse(BaseModel):
    global_max_bandwidth_kbps: float
    optimization_interval_sec: int
    active_optimizer: str
    max_offline_queue_size: int
    ai_api_key: Optional[str] = None
    global_ai_enabled: bool
    security_actions_enabled: bool = True

    class Config:
        from_attributes = True

class ServerConfigUpdate(BaseModel):
    global_max_bandwidth_kbps: Optional[float] = Field(None, ge=0.01)
    optimization_interval_sec: Optional[int] = Field(None, ge=1, le=3600)
    active_optimizer: Optional[str] = Field(None, pattern="^(genetic|proportional_fair|pso|abc|simulated_annealing|max_min_fair)$")
    max_offline_queue_size: Optional[int] = Field(None, ge=10, le=10000)
    ai_api_key: Optional[str] = None
    global_ai_enabled: Optional[bool] = None
    security_actions_enabled: Optional[bool] = Field(
        None, description="False: RiskEngine skor/aksiyon hesaplayıp loglar ama BLOCK_APP/RESTRICT/ISOLATE/LOCKDOWN istemciye gönderilmez (test modu)."
    )

class PriorityUpdate(BaseModel):
    pc_priority: int = Field(..., ge=1, le=10, description="Cihaz oncelik degeri (1=En Dusuk, 10=En Kritik)")

class EventResponse(BaseModel):
    kategori: str
    mesaj: str
    zaman_damgasi: str

    class Config:
        from_attributes = True
class DurationsUpdate(BaseModel):
    restrict_duration: Optional[int] = None
    isolate_duration: Optional[int] = None
    lockdown_duration: Optional[int] = None
    telemetry_interval: Optional[int] = Field(
        None, ge=5, le=300,
        description="Telemetri gonderim sikligi (saniye). Min: 5s, Max: 300s"
    )

class ManualAction(BaseModel):
    action: str = Field(..., description="Aksiyon tipi: RESTRICT, ISOLATE, LOCKDOWN, RECOVER")
    duration: Optional[int] = Field(None, description="Saniye cinsinden custom karantina suresi")

class SystemEventResponse(BaseModel):
    id: int
    kategori: str
    olay_tipi: str
    mesaj: str
    istemci_id: Optional[str] = None
    zaman_damgasi: str

    class Config:
        from_attributes = True

class LogResponse(BaseModel):
    id: int
    istemci_id: str
    kategori: str
    mesaj: str
    skor: float
    aksiyon: Optional[str] = None
    app_name: Optional[str] = None
    app_hash: Optional[str] = None
    zaman_damgasi: str

    class Config:
        from_attributes = True

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class EnrollRequest(BaseModel):
    pc_name: str = Field(..., description="İstemci PC adı")
    csr_pem: str = Field(..., description="PEM formatında CSR")
    token: str = Field(..., description="Bootstrap kayıt token'ı")

class EnrollResponse(BaseModel):
    cert_pem: str
    ca_pem: str

class RenewRequest(BaseModel):
    pc_name: str = Field(..., description="İstemci PC adı")
    current_cert_pem: str = Field(..., description="Mevcut istemci sertifikası PEM")
    new_csr_pem: str = Field(..., description="Yeni PEM formatında CSR")

class RenewResponse(BaseModel):
    cert_pem: str
    ca_pem: str

class CertificateMetadataResponse(BaseModel):
    id: int
    istemci_id: str
    serial_number: str
    fingerprint: str
    created_at: str
    expires_at: str
    status: str

    class Config:
        from_attributes = True

# Helper function to trigger whitelist sync over MQTT
def trigger_whitelist_sync(pc_name: str):
    try:
        # receiver_server modülü doğrudan import edilmeden registry üzerinden çağrılır
        # (Dairesel import önlemek için CallbackRegistry kullanılır)
        if CallbackRegistry.is_registered("send_whitelist"):
            import threading
            threading.Thread(
                target=lambda: CallbackRegistry.trigger("send_whitelist", pc_name),
                daemon=True
            ).start()
        else:
            logger.warning("[SYNC] 'send_whitelist' event'i registry'de kayitli degil. Receiver server baslatilmamis olabilir.")
    except Exception as e:
        logger.error(f"[SYNC] Whitelist senkronizasyon tetikleme hatasi: {e}")

# ======================= API ENDPOINTS =======================

@app.post("/api/v1/login", response_model=LoginResponse)
def login(data: LoginRequest, _https=Depends(enforce_https)):
    """Admin girişi yapar ve JWT access token döner."""
    if not check_rate_limit("login_attempt", limit=5, window=60):
        raise HTTPException(status_code=429, detail="Cok fazla giris denemesi. Lutfen 1 dakika sonra tekrar deneyin.")
        
    if data.username == ADMIN_USERNAME and data.password == ADMIN_PASSWORD:
        token = SimpleJWT.create_token({"sub": "admin"}, expires_in=3600)
        return {"access_token": token, "token_type": "bearer"}
        
    raise HTTPException(status_code=401, detail="Kullanici adi veya sifre hatali.")

@app.post("/api/v1/enroll", response_model=EnrollResponse)
def enroll_client(data: EnrollRequest, db=Depends(get_db), _https=Depends(enforce_https)):
    """İstemcinin ilk kez sertifika almasını sağlar. Bootstrap token gerektirir."""
    import datetime
    # Rate Limiting
    if not check_rate_limit(f"enroll_{data.pc_name}", limit=3, window=60):
        raise HTTPException(status_code=429, detail="Bu cihaz icin cok fazla kayit denemesi. Lutfen 1 dakika bekleyin.")
        
    # Bootstrap Token Doğrulaması
    expected_token = os.environ.get("REGISTRATION_TOKEN", "")
    if not expected_token:
        if getattr(config, "PRODUCTION", False):
            raise HTTPException(status_code=500, detail="Sunucu hatasi: Uretim modunda REGISTRATION_TOKEN ortam degiskeni tanimlanmak zorundadir!")
        else:
            expected_token = config.REGISTRATION_TOKEN
            
    if data.token != expected_token:
        raise HTTPException(status_code=401, detail="Gecersiz bootstrap kayit token'i.")
        
    try:
        # CSR'yi CA ile imzala
        cert_pem, serial_num, fingerprint, expires_at = cert_enrollment.sign_csr(data.csr_pem, data.pc_name)
        
        # Cihaz tablosunda istemci yoksa otomatik onboarding yap
        device = db.query(Istemci).filter_by(id=data.pc_name).first()
        if not device:
            device = Istemci(
                id=data.pc_name,
                pc_level="Standart_Seviye",
                mevcut_puan=0.0,
                risk_durumu=False,
                son_gorulme=datetime.datetime.now(datetime.timezone.utc)
            )
            db.add(device)
            db.commit()
            
        # Eski sertifikaları EXPIRED yap
        db.query(IstemciSertifikasi).filter_by(istemci_id=data.pc_name, status="ACTIVE").update({"status": "EXPIRED"})
        db.commit()
        
        # Yeni sertifikayı kaydet
        db_cert = IstemciSertifikasi(
            istemci_id=data.pc_name,
            serial_number=serial_num,
            fingerprint=fingerprint,
            expires_at=expires_at,
            status="ACTIVE"
        )
        db.add(db_cert)
        
        # Denetim Günlüğü logu
        sys_event = SistemOlaylari(
            kategori="GUVENLIK",
            olay_tipi="OTOMATIK_AKSIYON",
            mesaj=f"Cihaz basariyla kaydoldu (Auto-Enroll): {data.pc_name} (Serial: {serial_num})",
            istemci_id=data.pc_name
        )
        db.add(sys_event)
        db.commit()
        
        # Standart X.509 CRL listesini guncelle
        cert_enrollment.update_crl_file(db)
        
        # CA sertifikasını yükle
        _, ca_cert = cert_enrollment.load_ca()
        from cryptography.hazmat.primitives import serialization
        ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        
        return EnrollResponse(cert_pem=cert_pem, ca_pem=ca_pem)
        
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as e:
        logger.error(f"[ENROLL] Sertifika kaydi sirasinda hata: {e}")
        raise HTTPException(status_code=500, detail=f"Sertifika kayit hatasi: {e}")

@app.post("/api/v1/renew", response_model=RenewResponse)
def renew_client(data: RenewRequest, db=Depends(get_db), _https=Depends(enforce_https)):
    """İstemcinin mevcut sertifikasını yenilemesini sağlar. Eski sertifika doğrulaması gerektirir."""
    # Rate Limiting
    if not check_rate_limit(f"renew_{data.pc_name}", limit=5, window=60):
        raise HTTPException(status_code=429, detail="Bu cihaz icin cok fazla yenileme denemesi. Lutfen bekleyin.")
        
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        
        # 1. Mevcut sertifikayı doğrula (CA imzalı mı?)
        try:
            current_cert = x509.load_pem_x509_certificate(data.current_cert_pem.encode('utf-8'))
            ca_key, ca_cert = cert_enrollment.load_ca()
            # CA imzası kontrolü
            ca_cert.public_key().verify(
                current_cert.signature,
                current_cert.tbs_certificate_bytes,
                current_cert.signature_algorithm_parameters,
                current_cert.signature_hash_algorithm
            )
        except Exception as sign_err:
            raise HTTPException(status_code=401, detail=f"Mevcut sertifika CA imzasi dogrulamasi basarisiz: {sign_err}")
            
        # 2. Expiration kontrolü
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        not_valid_after = getattr(current_cert, "not_valid_after_utc", None)
        if not_valid_after is None:
            not_valid_after = current_cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
            
        if not_valid_after < now:
            raise HTTPException(status_code=401, detail="Mevcut sertifikanin suresi zaten dolmus. Yeniden kayit (Enroll) olmalisiniz.")
            
        # 3. DB'de aktif kayıt ve fingerprint eşleşmesi kontrolü
        fingerprint = cert_enrollment.get_cert_fingerprint(current_cert)
        db_cert = db.query(IstemciSertifikasi).filter_by(fingerprint=fingerprint, status="ACTIVE").first()
        if not db_cert or db_cert.istemci_id != data.pc_name:
            raise HTTPException(status_code=403, detail="Mevcut sertifika aktif degil veya talep eden cihaz adı ile eslesmiyor.")
            
        # 4. Yeni CSR'yi CA ile imzala
        cert_pem, serial_num, new_fingerprint, expires_at = cert_enrollment.sign_csr(data.new_csr_pem, data.pc_name)
        
        # 5. Eski sertifikayı EXPIRED yap, yenisini ACTIVE yap
        db_cert.status = "EXPIRED"
        
        new_db_cert = IstemciSertifikasi(
            istemci_id=data.pc_name,
            serial_number=serial_num,
            fingerprint=new_fingerprint,
            expires_at=expires_at,
            status="ACTIVE"
        )
        db.add(new_db_cert)
        
        # Olay logu yaz
        sys_event = SistemOlaylari(
            kategori="GUVENLIK",
            olay_tipi="OTOMATIK_AKSIYON",
            mesaj=f"Cihaz sertifikasi otomatik yenilendi (Auto-Renew): {data.pc_name} (Yeni Serial: {serial_num})",
            istemci_id=data.pc_name
        )
        db.add(sys_event)
        db.commit()
        
        # Standart X.509 CRL listesini guncelle
        cert_enrollment.update_crl_file(db)
        
        ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        return RenewResponse(cert_pem=cert_pem, ca_pem=ca_pem)
        
    except HTTPException:
        raise
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as e:
        logger.error(f"[RENEW] Sertifika yenileme hatasi: {e}")
        raise HTTPException(status_code=500, detail=f"Sertifika yenileme hatasi: {e}")

@app.get("/api/v1/certificates/{pc_name}", response_model=List[CertificateMetadataResponse])
def get_client_certificates(pc_name: str, db=Depends(get_db), token=Depends(verify_admin_token)):
    """Belirli bir istemcinin tüm sertifika geçmişini listeler."""
    certs = db.query(IstemciSertifikasi).filter_by(istemci_id=pc_name).order_by(IstemciSertifikasi.created_at.desc()).all()
    result = []
    for c in certs:
        result.append(CertificateMetadataResponse(
            id=c.id,
            istemci_id=c.istemci_id,
            serial_number=c.serial_number,
            fingerprint=c.fingerprint,
            created_at=(c.created_at.isoformat() + ("Z" if "+" not in c.created_at.isoformat() else "")) if c.created_at else "",
            expires_at=(c.expires_at.isoformat() + ("Z" if "+" not in c.expires_at.isoformat() else "")) if c.expires_at else "",
            status=c.status
        ))
    return result

@app.post("/api/v1/certificates/{serial}/revoke")
def revoke_certificate(serial: str, db=Depends(get_db), token=Depends(verify_admin_token)):
    """Belirli bir sertifikayı iptal (revoke) eder."""
    cert = db.query(IstemciSertifikasi).filter_by(serial_number=serial).first()
    if not cert:
        raise HTTPException(status_code=404, detail="Sertifika bulunamadi.")
        
    cert.status = "REVOKED"
    db.commit()
    
    # Denetim logu yaz
    sys_event = SistemOlaylari(
        kategori="GUVENLIK",
        olay_tipi="MANUEL_KOMUT",
        mesaj=f"Admin sertifikayi iptal (revoke) etti. Serial: {serial} | Cihaz: {cert.istemci_id}",
        istemci_id=cert.istemci_id
    )
    db.add(sys_event)
    db.commit()
    
    # Standart X.509 CRL listesini guncelle
    cert_enrollment.update_crl_file(db)
    
    logger.warning(f"[REVOCATION] Sertifika iptal edildi: Serial {serial} | Cihaz: {cert.istemci_id}")
    return {"status": "success", "message": f"Sertifika {serial} basariyla iptal edildi."}

@app.get("/api/events", response_model=List[EventResponse])
def get_events(db=Depends(get_db), token=Depends(verify_admin_token)):
    """Sistemdeki en son olayları (logları) listeler."""
    # Sistem olaylari ve güvenlik loglarini birlestirebilir veya sadece LogKaydi dondurebiliriz
    logs = db.query(LogKaydi).order_by(LogKaydi.zaman_damgasi.desc()).limit(20).all()
    result = []
    for l in logs:
        result.append(EventResponse(
            kategori=l.kategori or "INFO",
            mesaj=l.mesaj or "",
            zaman_damgasi=(l.zaman_damgasi.isoformat() + ("Z" if "+" not in l.zaman_damgasi.isoformat() else "")) if l.zaman_damgasi else ""
        ))
    return result

@app.get("/api/devices", response_model=List[DeviceResponse])
def get_devices(db=Depends(get_db), token=Depends(verify_admin_token)):
    """Sistemdeki tüm kayıtlı cihazları listeler."""
    devices = db.query(Istemci).all()
    result = []
    for d in devices:
        result.append(DeviceResponse(
            id=d.id,
            ip_adresi=d.ip_adresi,
            pc_level=d.pc_level,
            pc_priority=getattr(d, 'pc_priority', 5),
            mevcut_puan=d.mevcut_puan,
            risk_durumu=d.risk_durumu,
            son_gorulme=(d.son_gorulme.isoformat() + ("Z" if "+" not in d.son_gorulme.isoformat() else "")) if d.son_gorulme else "",
            restrict_duration=d.restrict_duration,
            isolate_duration=d.isolate_duration,
            lockdown_duration=d.lockdown_duration,
            telemetry_interval=d.telemetry_interval
        ))
    return result

@app.get("/api/devices/{pc_name}/whitelist", response_model=List[WhitelistResponse])
def get_device_whitelist(pc_name: str, db=Depends(get_db), token=Depends(verify_admin_token)):
    """Belirli bir cihazın whitelist kayıtlarını ve küresel kayıtları listeler."""
    device = db.query(Istemci).filter_by(id=pc_name).first()
    if not device:
        raise HTTPException(status_code=404, detail="Cihaz bulunamadi.")
    
    whitelist = db.query(BeyazListe).filter(
        (BeyazListe.istemci_id == pc_name) | (BeyazListe.istemci_id == None)
    ).all()
    return whitelist

@app.post("/api/devices/{pc_name}/whitelist", response_model=WhitelistResponse)
def add_device_whitelist(pc_name: str, data: WhitelistCreate, db=Depends(get_db), token=Depends(verify_admin_token)):
    """Belirli bir cihaza özel beyaz liste (whitelist) kaydı ekler."""
    device = db.query(Istemci).filter_by(id=pc_name).first()
    if not device:
        raise HTTPException(status_code=404, detail="Cihaz bulunamadi.")
    
    # Hash çakışması kontrolü
    exists = db.query(BeyazListe).filter_by(hash_sha256=data.hash_sha256).first()
    if exists:
        raise HTTPException(status_code=400, detail="Bu hash degeri zaten beyaz listede kayitli.")
    
    new_entry = BeyazListe(
        islem_adi=data.islem_adi,
        hash_sha256=data.hash_sha256,
        aciklama=data.aciklama,
        istemci_id=pc_name
    )
    db.add(new_entry)
    db.commit()
    db.refresh(new_entry)
    
    # Cihaza beyaz listeyi tekrar göndererek canlı senkronize et
    trigger_whitelist_sync(pc_name)
    
    # Denetim Günlüğüne Kaydet
    sys_event = SistemOlaylari(
        kategori="ADMIN",
        olay_tipi="MANUEL_KOMUT",
        mesaj=f"Admin tarafından beyaz listeye yeni uygulama eklendi: {data.islem_adi} ({data.hash_sha256[:16]}...)",
        istemci_id=pc_name
    )
    db.add(sys_event)
    db.commit()
    
    return new_entry

@app.delete("/api/devices/{pc_name}/whitelist/{app_hash}")
def delete_device_whitelist(pc_name: str, app_hash: str, db=Depends(get_db), token=Depends(verify_admin_token)):
    """Cihaz beyaz listesinden bir hash kaydı siler."""
    device = db.query(Istemci).filter_by(id=pc_name).first()
    if not device:
        raise HTTPException(status_code=404, detail="Cihaz bulunamadi.")
        
    entry = db.query(BeyazListe).filter_by(hash_sha256=app_hash, istemci_id=pc_name).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Beyaz liste kaydi bulunamadi.")
        
    islem_adi = entry.islem_adi
    db.delete(entry)
    db.commit()
    
    # Canlı senkronize et
    trigger_whitelist_sync(pc_name)
    
    # Denetim Günlüğüne Kaydet
    sys_event = SistemOlaylari(
        kategori="ADMIN",
        olay_tipi="MANUEL_KOMUT",
        mesaj=f"Admin tarafından beyaz listeden uygulama silindi: {islem_adi} ({app_hash[:16]}...)",
        istemci_id=pc_name
    )
    db.add(sys_event)
    db.commit()
    
    return {"status": "success", "message": "Beyaz liste kaydi silindi."}

@app.patch("/api/devices/{pc_name}/durations", response_model=DeviceResponse)
def update_device_durations(pc_name: str, data: DurationsUpdate, db=Depends(get_db), token=Depends(verify_admin_token)):
    """Cihaz bazlı aksiyon ve karantina sürelerini günceller."""
    device = db.query(Istemci).filter_by(id=pc_name).first()
    if not device:
        raise HTTPException(status_code=404, detail="Cihaz bulunamadi.")
        
    if data.restrict_duration is not None:
        device.restrict_duration = data.restrict_duration
    if data.isolate_duration is not None:
        device.isolate_duration = data.isolate_duration
    if data.lockdown_duration is not None:
        device.lockdown_duration = data.lockdown_duration

    # Telemetri sıklığı güncelleme + MQTT bildirimi
    if data.telemetry_interval is not None:
        device.telemetry_interval = data.telemetry_interval
        try:
            # receiver_server modülü doğrudan import edilmeden mqtt_client registry üzerinden alınır
            if CallbackRegistry.is_registered("get_mqtt_client"):
                _mqtt = CallbackRegistry.trigger("get_mqtt_client")
                if _mqtt and _mqtt.is_connected():
                    cmd = {"action": "UPDATE_TELEMETRY_INTERVAL", "interval": data.telemetry_interval}
                    encrypted = CryptoHelper.encrypt_and_compress(cmd)
                    _mqtt.publish(f"network/control/{pc_name}", encrypted, qos=1)
                    logger.info(f"[TELEMETRI] {pc_name} cihazina yeni siklik bildirildi: {data.telemetry_interval}s")
                else:
                    logger.warning(f"[TELEMETRI] MQTT baglantisi yok, {pc_name} icin interval komutu gonderilemedi.")
            else:
                logger.warning("[TELEMETRI] 'get_mqtt_client' event'i kayitli degil. Sunucu baslatilmamis olabilir.")
        except Exception as e:
            logger.warning(f"[TELEMETRI] Interval MQTT komutu hatasi: {e}")
        
    db.commit()
    db.refresh(device)
    
    # Denetim Günlüğüne Kaydet
    sys_event = SistemOlaylari(
        kategori="ADMIN",
        olay_tipi="MANUEL_KOMUT",
        mesaj=(
            f"Admin cihaz ayarlarini guncelledi "
            f"(Restrict: {device.restrict_duration}s | Isolate: {device.isolate_duration}s | "
            f"Lockdown: {device.lockdown_duration}s | Telemetri: {device.telemetry_interval}s)"
        ),
        istemci_id=pc_name
    )
    db.add(sys_event)
    db.commit()
    
    return DeviceResponse(
        id=device.id,
        ip_adresi=device.ip_adresi,
        pc_level=device.pc_level,
        pc_priority=getattr(device, 'pc_priority', 5),  # Düzeltme: önce eksikti
        mevcut_puan=device.mevcut_puan,
        risk_durumu=device.risk_durumu,
        son_gorulme=(device.son_gorulme.isoformat() + ("Z" if "+" not in device.son_gorulme.isoformat() else "")) if device.son_gorulme else "",
        restrict_duration=device.restrict_duration,
        isolate_duration=device.isolate_duration,
        lockdown_duration=device.lockdown_duration,
        telemetry_interval=device.telemetry_interval
    )

@app.get("/api/devices/{pc_name}/cooldown")
def get_device_cooldown(pc_name: str, db=Depends(get_db), token=Depends(verify_admin_token)):
    """Cihazın aktif karantina/kısıtlama durumunu ve kalan süresini döner.
    
    Dönen alanlar:
      - active (bool): Aktif bir cooldown var mı?
      - seconds_remaining (int): Kalan saniye (0 ise süresi dolmuş/yok).
      - expires_at (str | null): Bitiş zamanı ISO 8601.
      - last_action (str | null): Son gönderilen aksiyon tipi (log'dan okunur).
    """
    import workers

    device = db.query(Istemci).filter_by(id=pc_name).first()
    if not device:
        raise HTTPException(status_code=404, detail="Cihaz bulunamadi.")

    with workers._cooldowns_lock:
        expires_ts = workers.ACTIVE_COOLDOWNS.get(pc_name)

    now = time.time()
    if expires_ts and expires_ts > now:
        remaining = int(expires_ts - now)
        import datetime as _dt
        expires_iso = _dt.datetime.fromtimestamp(expires_ts, tz=_dt.timezone.utc).isoformat()
        active = True
    else:
        remaining = 0
        expires_iso = None
        active = False

    # Son aksiyon tipini en yeni sistem olayından çek
    last_event = (
        db.query(SistemOlaylari)
        .filter(
            SistemOlaylari.istemci_id == pc_name,
            SistemOlaylari.olay_tipi.in_(["MANUEL_KOMUT", "OTOMATIK_AKSIYON", "RECOVER"])
        )
        .order_by(SistemOlaylari.zaman_damgasi.desc())
        .first()
    )
    last_action = None
    if last_event:
        msg = (last_event.mesaj or "").upper()
        for act in ["LOCKDOWN", "ISOLATE", "RESTRICT", "RECOVER"]:
            if act in msg:
                last_action = act
                break

    return {
        "pc_name": pc_name,
        "active": active,
        "seconds_remaining": remaining,
        "expires_at": expires_iso,
        "last_action": last_action,
        "risk_durumu": device.risk_durumu,
    }


@app.post("/api/devices/{pc_name}/action")
def trigger_manual_action(pc_name: str, data: ManualAction, db=Depends(get_db), token=Depends(verify_admin_token)):
    """Cihaza manuel olarak anlık koruma/karantina/kurtarma (action) komutu gönderir."""
    device = db.query(Istemci).filter_by(id=pc_name).first()
    if not device:
        raise HTTPException(status_code=404, detail="Cihaz bulunamadi.")
        
    action_upper = data.action.upper()
    if action_upper not in ["RESTRICT", "ISOLATE", "LOCKDOWN", "RECOVER"]:
        raise HTTPException(status_code=400, detail="Gecersiz aksiyon tipi. Sadece RESTRICT, ISOLATE, LOCKDOWN, RECOVER olabilir.")

    import workers
    from risk_engine import get_policy

    # receiver_server modülü doğrudan import edilmeden mqtt_client registry üzerinden alınır
    _mqtt = None
    if CallbackRegistry.is_registered("get_mqtt_client"):
        _mqtt = CallbackRegistry.trigger("get_mqtt_client")

    if not _mqtt or not _mqtt.is_connected():
        raise HTTPException(status_code=503, detail="MQTT broker baglantisi aktif degil, komut iletilemedi.")

    # 1. RECOVER (KURTARMA) Senaryosu
    if action_upper == "RECOVER":
        # Aktif cooldown zamanlayıcısını ve Event'i iptal et
        with workers._cooldowns_lock:
            workers.ACTIVE_COOLDOWNS.pop(pc_name, None)
            ev = workers.COOLDOWN_EVENTS.pop(pc_name, None)
            if ev:
                ev.set() # Uyuyan recover thread'ini uyandır (iptal et)
                
        # Cihaz durumunu veritabanında sıfırla
        device.risk_durumu = False
        device.mevcut_puan = 0.0
        db.commit()
        
        # İstemciye RECOVER komutu gönder
        cmd = {"action": "RECOVER"}
        encrypted = CryptoHelper.encrypt_and_compress(cmd)
        _mqtt.publish(f"network/control/{pc_name}", encrypted, qos=1)
        
        # Olay logu yaz
        sys_event = SistemOlaylari(
            kategori="ADMIN",
            olay_tipi="RECOVER",
            mesaj="Admin manuel RECOVER (kurtarma) komutu gonderdi.",
            istemci_id=pc_name
        )
        db.add(sys_event)
        db.commit()
        
        logger.warning(f"[MANUEL-RECOVER] {pc_name} karantinadan manuel olarak cikarildi.")
        return {"status": "success", "message": "Manuel recover komutu gonderildi."}

    # 2. Kısıtlama / Karantina Senaryosu (RESTRICT, ISOLATE, LOCKDOWN)
    custom_dur = data.duration
    if custom_dur is None:
        # Oncelik politikasından cihaza ozel sureyi cek
        pc_pri = getattr(device, 'pc_priority', 5)
        policy = get_policy(pc_pri)
        if action_upper == "RESTRICT":
            custom_dur = device.restrict_duration if device.restrict_duration is not None else policy["restrict_duration_sec"]
        elif action_upper == "ISOLATE":
            custom_dur = device.isolate_duration if device.isolate_duration is not None else policy["isolate_duration_sec"]
        elif action_upper == "LOCKDOWN":
            custom_dur = device.lockdown_duration if device.lockdown_duration is not None else policy["lockdown_duration_sec"]

    # Cooldown işlemleri
    with workers._cooldowns_lock:
        # Önceki cooldown varsa iptal et
        prev_ev = workers.COOLDOWN_EVENTS.pop(pc_name, None)
        if prev_ev:
            prev_ev.set()
            
        # Yeni Event ve cooldown oluştur
        event = threading.Event()
        workers.COOLDOWN_EVENTS[pc_name] = event
        workers.ACTIVE_COOLDOWNS[pc_name] = time.time() + custom_dur

    # Veritabanında risk durumunu güncelle
    device.risk_durumu = True
    device.mevcut_puan = 85.0  # Manuel karantina varsayılan puanı
    db.commit()

    # İstemciye MQTT üzerinden şifreli komut gönder
    cmd = {"action": action_upper}
    encrypted = CryptoHelper.encrypt_and_compress(cmd)
    _mqtt.publish(f"network/control/{pc_name}", encrypted, qos=1)

    # Recovery Thread'i başlat (Eğer süre > 0 ise otomatik kurtarma devrede olsun)
    if custom_dur > 0:
        def delayed_recover(_name=pc_name, _dur=custom_dur, _ev=event):
            is_cancelled = _ev.wait(timeout=_dur)
            if is_cancelled:
                logger.info(f"[COOLDOWN] Manuel baslatilan cooldown iptal edildi: {_name}")
                return

            with workers._cooldowns_lock:
                target_time = workers.ACTIVE_COOLDOWNS.get(_name, 0)
            if target_time > time.time() + 0.1:
                return

            # RECOVER Gönder
            rec_cmd = {"action": "RECOVER"}
            enc_rec = CryptoHelper.encrypt_and_compress(rec_cmd)
            if CallbackRegistry.is_registered("get_mqtt_client"):
                _rs_mqtt = CallbackRegistry.trigger("get_mqtt_client")
                if _rs_mqtt:
                    _rs_mqtt.publish(f"network/control/{_name}", enc_rec, qos=1)

            # DB Güncelle
            db_rec = SessionLocal()
            try:
                sys_ev = database.SistemOlaylari(
                    kategori="COOLDOWN",
                    olay_tipi="COOLDOWN_EXPIRED",
                    mesaj=f"Manuel baslatilan karantina suresi doldu ({_dur}sn). Cihaz otomatik kurtarildi.",
                    istemci_id=_name
                )
                db_rec.add(sys_ev)
                
                cli_rec = db_rec.query(database.Istemci).filter_by(id=_name).first()
                if cli_rec:
                    cli_rec.risk_durumu = False
                    cli_rec.mevcut_puan = 0.0
                db_rec.commit()
            except Exception as db_err:
                logger.error(f"[COOLDOWN] Manuel recovery DB hatasi: {db_err}")
                db_rec.rollback()
            finally:
                db_rec.close()

        t = threading.Thread(target=delayed_recover, daemon=True)
        t.start()

    # Sistem Olayları Logu Yaz
    sys_event = SistemOlaylari(
        kategori="ADMIN",
        olay_tipi="MANUEL_KOMUT",
        mesaj=f"Admin manuel karantina komutu gonderdi: {action_upper} (Sure: {custom_dur}sn)",
        istemci_id=pc_name
    )
    db.add(sys_event)
    db.commit()

    logger.warning(f"[MANUEL-KOMUT] {pc_name} icin {action_upper} eylemi tetiklendi (Sure: {custom_dur}sn)")
    return {"status": "success", "message": f"Manuel {action_upper} komutu gonderildi."}

@app.get("/api/policies", response_model=List[PolicyResponse])
def get_all_policies(db=Depends(get_db), token=Depends(verify_admin_token)):
    """Tum oncelik seviyelerinin politikalarini listeler (10'dan 1'e siralanmis)."""
    rows = db.query(OncelikPolitikalari).order_by(OncelikPolitikalari.priority_level.desc()).all()
    return rows

@app.get("/api/policies/{level}", response_model=PolicyResponse)
def get_policy_by_level(level: int, db=Depends(get_db), token=Depends(verify_admin_token)):
    """Belirli bir oncelik seviyesinin politikasini dondurur."""
    row = db.query(OncelikPolitikalari).filter_by(priority_level=level).first()
    if not row:
        raise HTTPException(status_code=404, detail=f"Oncelik seviyesi {level} bulunamadi.")
    return row

@app.put("/api/policies/{level}", response_model=PolicyResponse)
def update_policy(level: int, data: PolicyUpdate, db=Depends(get_db), token=Depends(verify_admin_token)):
    """Belirli bir oncelik seviyesinin politikasini gunceller. DB ve RAM cache esit zamanda yazilir."""
    row = db.query(OncelikPolitikalari).filter_by(priority_level=level).first()
    if not row:
        raise HTTPException(status_code=404, detail=f"Oncelik seviyesi {level} bulunamadi.")

    update_fields = data.model_dump(exclude_unset=True)
    for field, value in update_fields.items():
        setattr(row, field, value)
    db.commit()
    db.refresh(row)

    # RAM onbellegini yenile
    from risk_engine import load_policy_cache
    load_policy_cache(db)

    # Denetim logu
    sys_event = SistemOlaylari(
        kategori="ADMIN",
        olay_tipi="MANUEL_KOMUT",
        mesaj=f"Admin Oncelik {level} politikasini guncelledi: {list(update_fields.keys())}"
    )
    db.add(sys_event)
    db.commit()
    logger.info(f"[POLITIKA] Oncelik {level} politikasi guncellendi ve RAM cache yenilendi.")
    return row

@app.get("/api/server-config", response_model=ServerConfigResponse)
def get_server_config(db=Depends(get_db), token=Depends(verify_admin_token)):
    """Global sunucu ayarlarini dondurur.
    ai_api_key DB'de kayitli degilse .env ortam degiskeninden (AI_API_KEY) okur.
    """
    logger.info(f"[DEBUG] get_server_config called! Env AI_API_KEY present: {bool(os.environ.get('AI_API_KEY'))}")
    cfg = db.query(SunucuAyarlari).filter_by(id=1).first()
    if not cfg:
        raise HTTPException(status_code=404, detail="Sunucu ayarlari bulunamadi.")
    # DB'de key yoksa ortam degiskeninden fallback yap
    if not cfg.ai_api_key:
        env_key = os.environ.get("AI_API_KEY")
        if env_key:
            cfg.ai_api_key = env_key
            db.commit()
            logger.info("[CONFIG] AI_API_KEY .env'den veritabanina yazildi.")
    return cfg

@app.put("/api/server-config", response_model=ServerConfigResponse)
def update_server_config(data: ServerConfigUpdate, db=Depends(get_db), token=Depends(verify_admin_token)):
    """Global sunucu ayarlarini gunceller."""
    cfg = db.query(SunucuAyarlari).filter_by(id=1).first()
    if not cfg:
        raise HTTPException(status_code=404, detail="Sunucu ayarlari bulunamadi.")
    update_fields = data.model_dump(exclude_unset=True)
    for field, value in update_fields.items():
        setattr(cfg, field, value)
    db.commit()
    db.refresh(cfg)
    sys_event = SistemOlaylari(
        kategori="ADMIN",
        olay_tipi="MANUEL_KOMUT",
        mesaj=f"Admin global sunucu ayarlarini guncelledi: {list(update_fields.keys())}"
    )
    db.add(sys_event)
    db.commit()
    return cfg

@app.patch("/api/devices/{pc_name}/priority")
def update_device_priority(pc_name: str, data: PriorityUpdate, db=Depends(get_db), token=Depends(verify_admin_token)):
    """Cihazin oncelik (priority) seviyesini gunceller (1-10) ve istemciye anlık bildirir."""
    device = db.query(Istemci).filter_by(id=pc_name).first()
    if not device:
        raise HTTPException(status_code=404, detail="Cihaz bulunamadi.")
    old_priority = getattr(device, 'pc_priority', 5)
    device.pc_priority = data.pc_priority
    db.commit()
    sys_event = SistemOlaylari(
        kategori="ADMIN",
        olay_tipi="MANUEL_KOMUT",
        mesaj=f"Admin cihaz onceligi guncelledi: {pc_name} | {old_priority} -> {data.pc_priority}",
        istemci_id=pc_name
    )
    db.add(sys_event)
    db.commit()

    # İstemciye MQTT üzerinden anlık öncelik güncelleme komutu gönder
    try:
        if CallbackRegistry.is_registered("get_mqtt_client"):
            _mqtt = CallbackRegistry.trigger("get_mqtt_client")
            if _mqtt and _mqtt.is_connected():
                cmd = {"action": "UPDATE_PRIORITY", "priority": data.pc_priority}
                encrypted = CryptoHelper.encrypt_and_compress(cmd)
                _mqtt.publish(f"network/control/{pc_name}", encrypted, qos=1)
                logger.info(f"[ONCELIK] {pc_name} istemcisine yeni oncelik bildirildi: {data.pc_priority}")
            else:
                logger.warning(f"[ONCELIK] MQTT baglantisi yok, {pc_name} icin UPDATE_PRIORITY gonderilemedi.")
    except Exception as e:
        logger.warning(f"[ONCELIK] UPDATE_PRIORITY MQTT komutu hatasi: {e}")

    logger.info(f"[CIHAZ] {pc_name} onceligi {old_priority} -> {data.pc_priority} olarak guncellendi.")
    return {"status": "success", "pc_name": pc_name, "new_priority": data.pc_priority}


@app.get("/api/devices/{pc_name}/processes")
def request_process_list(pc_name: str, db=Depends(get_db), token=Depends(verify_admin_token)):
    """MQTT uzerinden istemciye surec listesi istegi gonderir. Istemci yaniti ayri bir MQTT kanalinda gelir."""
    device = db.query(Istemci).filter_by(id=pc_name).first()
    if not device:
        raise HTTPException(status_code=404, detail="Cihaz bulunamadi.")
    if not CallbackRegistry.is_registered("get_mqtt_client"):
        raise HTTPException(status_code=503, detail="MQTT kayitli degil.")
    _mqtt = CallbackRegistry.trigger("get_mqtt_client")
    if not _mqtt or not _mqtt.is_connected():
        raise HTTPException(status_code=503, detail="MQTT broker baglantisi aktif degil.")
    cmd = {"action": "REQUEST_PROCESS_LIST"}
    encrypted = CryptoHelper.encrypt_and_compress(cmd)
    _mqtt.publish(f"network/control/{pc_name}", encrypted, qos=1)
    logger.info(f"[PROCESS] {pc_name} icin surec listesi istegi gonderildi.")
    return {"status": "success", "message": f"{pc_name} cihazina surec listesi istegi gonderildi."}

@app.get("/api/devices/{pc_name}/processes/result")
def get_process_list_result(pc_name: str, db=Depends(get_db), token=Depends(verify_admin_token)):
    """Istemciden gelen surec listesi sonucunu Redis'ten okur."""
    device = db.query(Istemci).filter_by(id=pc_name).first()
    if not device:
        raise HTTPException(status_code=404, detail="Cihaz bulunamadi.")
        
    try:
        from workers import redis_mgr
        _r = redis_mgr.get()
        redis_key = f"process_list:{pc_name}"
        data = _r.get(redis_key)
        if data:
            import json
            return {"status": "success", "processes": json.loads(data)}
        else:
            return {"status": "pending", "message": "Surec listesi henuz ulasmadi veya zaman asimina ugradi."}
    except Exception as e:
        logger.error(f"[PROCESS] Redis'ten surec listesi okunurken hata: {e}")
        raise HTTPException(status_code=500, detail="Redis baglanti hatasi.")

@app.post("/api/devices/{pc_name}/kill-process")
def kill_process(pc_name: str, pid: int, process_name: str = "", db=Depends(get_db), token=Depends(verify_admin_token)):
    """MQTT uzerinden istemciye belirtilen PID'li sureci sonlandirma komutu gonderir."""
    device = db.query(Istemci).filter_by(id=pc_name).first()
    if not device:
        raise HTTPException(status_code=404, detail="Cihaz bulunamadi.")
    if not CallbackRegistry.is_registered("get_mqtt_client"):
        raise HTTPException(status_code=503, detail="MQTT kayitli degil.")
    _mqtt = CallbackRegistry.trigger("get_mqtt_client")
    if not _mqtt or not _mqtt.is_connected():
        raise HTTPException(status_code=503, detail="MQTT broker baglantisi aktif degil.")
    cmd = {"action": "KILL_PROCESS", "pid": pid, "process_name": process_name}
    encrypted = CryptoHelper.encrypt_and_compress(cmd)
    _mqtt.publish(f"network/control/{pc_name}", encrypted, qos=1)
    sys_event = SistemOlaylari(
        kategori="ADMIN",
        olay_tipi="MANUEL_KOMUT",
        mesaj=f"Admin surec sonlandirma komutu gonderdi: PID={pid} ({process_name}) -> {pc_name}",
        istemci_id=pc_name
    )
    db.add(sys_event)
    db.commit()
    logger.warning(f"[KILL-PROCESS] {pc_name} icin PID {pid} ({process_name}) sonlandirma komutu gonderildi.")
    return {"status": "success", "message": f"PID {pid} sonlandirma komutu gonderildi."}

# ===================== BLACKLIST & WHITELIST (KAPSAMLI) =====================

@app.get("/api/blacklist", response_model=List[BlacklistResponse])
def get_blacklist(db=Depends(get_db), token=Depends(verify_admin_token)):
    """Tum kara liste kayitlarini dondurur."""
    return db.query(KaraListe).order_by(KaraListe.id).all()

@app.post("/api/blacklist")
def add_blacklist(data: BlacklistCreate, db=Depends(get_db), token=Depends(verify_admin_token)):
    """Kara listeye yeni kayit(lar) ekler. priority_scopes veya device_scope_ids ile kapsamlanabilir."""
    if not data.hash_sha256 and not data.islem_adi:
        raise HTTPException(status_code=400, detail="Hash veya islem adi girilmelidir.")
    
    scopes_to_add = []
    
    if data.priority_scopes and len(data.priority_scopes) > 0:
        for p in data.priority_scopes:
            scopes_to_add.append({"priority_scope": p, "device_scope_id": None})
    elif data.device_scope_ids and len(data.device_scope_ids) > 0:
        for d in data.device_scope_ids:
            scopes_to_add.append({"priority_scope": None, "device_scope_id": d})
    else:
        scopes_to_add.append({"priority_scope": None, "device_scope_id": None})
        
    created_entries = []
    for scope in scopes_to_add:
        if data.hash_sha256:
            exists = db.query(KaraListe).filter_by(
                hash_sha256=data.hash_sha256, 
                priority_scope=scope["priority_scope"], 
                device_scope_id=scope["device_scope_id"]
            ).first()
            if exists:
                continue # Skip if already exists for this scope
                
            # Mutual exclusion: remove from whitelist if it exists there
            wl_exists = db.query(BeyazListe).filter_by(
                hash_sha256=data.hash_sha256,
                priority_scope=scope["priority_scope"],
                device_scope_id=scope["device_scope_id"]
            ).first()
            if wl_exists:
                db.delete(wl_exists)

        new_entry = KaraListe(
            islem_adi=data.islem_adi,
            hash_sha256=data.hash_sha256,
            risk_puani=data.risk_puani,
            aciklama=data.aciklama,
            priority_scope=scope["priority_scope"],
            device_scope_id=scope["device_scope_id"]
        )
        db.add(new_entry)
        created_entries.append(new_entry)
        
    db.commit()
    
    sys_event = SistemOlaylari(
        kategori="ADMIN",
        olay_tipi="MANUEL_KOMUT",
        mesaj=f"Kara listeye eklendi: {data.islem_adi or data.hash_sha256} | Toplam Scope: {len(created_entries)}"
    )
    db.add(sys_event)
    db.commit()
    return {"status": "success", "added_count": len(created_entries)}

@app.put("/api/blacklist/{entry_id}")
def update_blacklist(entry_id: int, data: BlacklistUpdate, db=Depends(get_db), token=Depends(verify_admin_token)):
    """Kara liste kaydinin aciklama ve risk puanini gunceller."""
    entry = db.query(KaraListe).filter_by(id=entry_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Kayit bulunamadi.")
    if data.aciklama is not None:
        entry.aciklama = data.aciklama
    if data.risk_puani is not None:
        entry.risk_puani = data.risk_puani
    db.commit()
    return {"status": "success", "message": "Kara liste kaydi guncellendi."}

@app.delete("/api/blacklist/{entry_id}")
def delete_blacklist(entry_id: int, db=Depends(get_db), token=Depends(verify_admin_token)):
    """Kara listeden kayit siler."""
    entry = db.query(KaraListe).filter_by(id=entry_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Kayit bulunamadi.")
    db.delete(entry)
    db.commit()
    return {"status": "success", "message": "Kara liste kaydi silindi."}

@app.get("/api/whitelist", response_model=List[WhitelistResponse])
def get_whitelist(db=Depends(get_db), token=Depends(verify_admin_token)):
    """Tum beyaz liste kayitlarini dondurur."""
    return db.query(BeyazListe).order_by(BeyazListe.id).all()

@app.post("/api/whitelist")
def add_whitelist(data: WhitelistCreate, db=Depends(get_db), token=Depends(verify_admin_token)):
    """Beyaz listeye yeni kayit(lar) ekler. priority_scopes veya device_scope_ids ile kapsamlanabilir."""
    scopes_to_add = []
    
    if data.priority_scopes and len(data.priority_scopes) > 0:
        for p in data.priority_scopes:
            scopes_to_add.append({"priority_scope": p, "device_scope_id": None})
    elif data.device_scope_ids and len(data.device_scope_ids) > 0:
        for d in data.device_scope_ids:
            scopes_to_add.append({"priority_scope": None, "device_scope_id": d})
    else:
        scopes_to_add.append({"priority_scope": None, "device_scope_id": None})
        
    created_entries = []
    for scope in scopes_to_add:
        exists = db.query(BeyazListe).filter_by(
            hash_sha256=data.hash_sha256,
            priority_scope=scope["priority_scope"],
            device_scope_id=scope["device_scope_id"]
        ).first()
        if exists:
            continue
            
        # Mutual exclusion: remove from blacklist if it exists there
        bl_exists = db.query(KaraListe).filter_by(
            hash_sha256=data.hash_sha256,
            priority_scope=scope["priority_scope"],
            device_scope_id=scope["device_scope_id"]
        ).first()
        if bl_exists:
            db.delete(bl_exists)

        new_entry = BeyazListe(
            islem_adi=data.islem_adi,
            hash_sha256=data.hash_sha256,
            aciklama=data.aciklama,
            istemci_id=data.istemci_id,
            priority_scope=scope["priority_scope"],
            device_scope_id=scope["device_scope_id"]
        )
        db.add(new_entry)
        created_entries.append(new_entry)
        
    db.commit()
    trigger_whitelist_sync(data.istemci_id or "")
    
    sys_event = SistemOlaylari(
        kategori="ADMIN",
        olay_tipi="MANUEL_KOMUT",
        mesaj=f"Beyaz listeye eklendi: {data.islem_adi or data.hash_sha256} | Toplam Scope: {len(created_entries)}"
    )
    db.add(sys_event)
    db.commit()
    return {"status": "success", "added_count": len(created_entries)}

@app.put("/api/whitelist/{entry_id}")
def update_whitelist(entry_id: int, data: WhitelistUpdate, db=Depends(get_db), token=Depends(verify_admin_token)):
    """Beyaz liste kaydinin aciklamasini gunceller."""
    entry = db.query(BeyazListe).filter_by(id=entry_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Kayit bulunamadi.")
    if data.aciklama is not None:
        entry.aciklama = data.aciklama
    db.commit()
    trigger_whitelist_sync(entry.istemci_id or "")
    return {"status": "success", "message": "Beyaz liste kaydi guncellendi."}

@app.delete("/api/whitelist/{entry_id}")
def delete_whitelist(entry_id: int, db=Depends(get_db), token=Depends(verify_admin_token)):
    """Beyaz listeden kayit siler."""
    entry = db.query(BeyazListe).filter_by(id=entry_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Kayit bulunamadi.")
    istemci = entry.istemci_id
    db.delete(entry)
    db.commit()
    trigger_whitelist_sync(istemci or "")
    return {"status": "success", "message": "Beyaz liste kaydi silindi."}

# ===================== LOGS API =====================

@app.get("/api/logs")
def get_logs(
    limit: int = 50, 
    offset: int = 0,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    pc_priority: Optional[int] = None,
    istemci_id: Optional[str] = None,
    db=Depends(get_db), 
    token=Depends(verify_admin_token)
):
    import datetime
    
    # Güvenlik tavanı: Tek seferde en fazla 500 kayıt çekilebilir
    limit = min(limit, 500)
    
    query = db.query(LogKaydi).outerjoin(Istemci)

    if start_date:
        try:
            start_dt = datetime.datetime.fromisoformat(start_date)
            # Eğer saat dilimi yoksa UTC kabul et
            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=datetime.timezone.utc)
            query = query.filter(LogKaydi.zaman_damgasi >= start_dt)
        except ValueError:
            pass

    if end_date:
        try:
            end_dt = datetime.datetime.fromisoformat(end_date)
            if end_dt.tzinfo is None:
                end_dt = end_dt.replace(tzinfo=datetime.timezone.utc)
            query = query.filter(LogKaydi.zaman_damgasi <= end_dt)
        except ValueError:
            pass
            
    if pc_priority is not None:
        query = query.filter(Istemci.pc_priority == pc_priority)
        
    if istemci_id:
        query = query.filter(LogKaydi.istemci_id.like(f"%{istemci_id}%"))
        
    query = query.order_by(LogKaydi.zaman_damgasi.desc())
    
    total_count = query.count()
    logs = query.offset(offset).limit(limit).all()
    
    result = []
    for log in logs:
        # Z eklentisi UI'nin doğru çevirmesini sağlar
        iso_zaman = log.zaman_damgasi.isoformat() if log.zaman_damgasi else None
        if iso_zaman and not iso_zaman.endswith("Z") and "+" not in iso_zaman:
            iso_zaman += "Z"
            
        item = {
            "id": log.id,
            "istemci_id": log.istemci_id,
            "kategori": log.kategori,
            "mesaj": log.mesaj,
            "skor": log.skor,
            "aksiyon": log.aksiyon,
            "app_name": log.app_name,
            "zaman_damgasi": iso_zaman,
            "pc_priority": log.istemci.pc_priority if log.istemci else None
        }
        result.append(item)
        
    return {
        "status": "success",
        "total": total_count,
        "logs": result
    }

# ===================== UI MOUNTING =====================
# Serve frontend static files
ui_dir = os.path.join(path_helper.get_base_dir(), "ui")
if not os.path.exists(ui_dir):
    os.makedirs(ui_dir, exist_ok=True)
    os.makedirs(os.path.join(ui_dir, "css"), exist_ok=True)
    os.makedirs(os.path.join(ui_dir, "js"), exist_ok=True)

app.mount("/ui", StaticFiles(directory=ui_dir, html=True), name="ui")

@app.get("/")
def redirect_to_ui():
    return RedirectResponse(url="/ui/")


def start_admin_api():
    """Uvicorn uzerinde admin API'yi baslatir (receiver_server tarafindan thread olarak cagirilir)."""
    import uvicorn
    try:
        cfg = uvicorn.Config(
            app=app,
            host="0.0.0.0",
            port=8000,
            log_level="error",
            access_log=False
        )
        server = uvicorn.Server(config=cfg)
        # Alt thread'de calisirken Windows signal handler kurma hatasini (ValueError) engelle
        server.install_signal_handlers = lambda: None
        logger.info("[ADMIN-API] Uvicorn sunucusu 8000 portunda dinlemeye basliyor...")
        server.run()
    except Exception as e:
        logger.critical(f"[ADMIN-API] Uvicorn baslatilirken kritik hata: {e}", exc_info=True)

if __name__ == "__main__":
    start_admin_api()