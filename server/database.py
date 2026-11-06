import os
import sys
import time
import logging
from datetime import datetime, timezone
from sqlalchemy import create_engine, text, Column, Integer, String, Float, DateTime, Boolean, ForeignKey, Text, UniqueConstraint
from sqlalchemy.orm import declarative_base, sessionmaker, relationship # Tabloların Python sınıfları olarak tanımlanması için temel şablon oluşturur.

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Database")

# config.py'yi bul ve import et (database.py server/ altında, config common/ altında)
_server_dir = os.path.dirname(os.path.abspath(__file__))
_common_dir = os.path.join(os.path.dirname(_server_dir), "common")
if _common_dir not in sys.path:
    sys.path.insert(0, _common_dir)
import app_config as _config

import path_helper

# Varsayılan PostgreSQL ve SQLite adresleri
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DATABASE_URL = "postgresql://postgres:root@localhost:5432/noc_sentinel_db"
DEFAULT_SQLITE_URL = f"sqlite:///{os.path.join(path_helper.get_persistent_dir(), 'server_fallback.db')}"

DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)
SQLITE_URL = os.getenv("SQLITE_URL", DEFAULT_SQLITE_URL)

Base = declarative_base()

# ======================= MODELLER =======================

class Istemci(Base):
    """Sistemdeki kayıtlı istemci makineleri temsil eder."""
    __tablename__ = "istemciler"

    id = Column(String, primary_key=True) # PC Adi
    ip_adresi = Column(String, nullable=True)
    pc_level = Column(String, default="Standart_Seviye")
    mevcut_puan = Column(Float, default=0.0)
    risk_durumu = Column(Boolean, default=False)
    son_gorulme = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    # Cihaza özel karantina/izolasyon süreleri (Saniye)
    restrict_duration = Column(Integer, nullable=True)
    isolate_duration = Column(Integer, nullable=True)
    lockdown_duration = Column(Integer, nullable=True)

    # Cihaza özel donanım telemetri gönderim sıklığı (Saniye)
    # None ise istemci varsayılan değeri (30s) kullanır.
    telemetry_interval = Column(Integer, nullable=True)

    # Cihaz Onceligi (1=En Dusuk, 10=En Kritik)
    # Bu deger admin panelinden degistirilebilir ve politika motorunda kullanilir.
    pc_priority = Column(Integer, default=5, nullable=False)

    loglar = relationship("LogKaydi", back_populates="istemci", cascade="all, delete-orphan")

class LogKaydi(Base):
    """İstemcilerden gelen log ve olay verileri."""
    __tablename__ = "log_kayitlari"

    id = Column(Integer, primary_key=True, autoincrement=True)
    istemci_id = Column(String, ForeignKey("istemciler.id"), index=True)
    kategori = Column(String, index=True)  # INFO, WARNING, CRITICAL, EMERGENCY
    mesaj = Column(String)
    skor = Column(Float, default=0.0)
    aksiyon = Column(String, nullable=True)
    app_name = Column(String, nullable=True)
    app_hash = Column(String, nullable=True)
    zaman_damgasi = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)

    # YENİ: Gerçek gecikme/kısıtlama ölçümü için istemci taraflı zaman damgaları
    # (unix epoch, saniye — float). NTP senkronizasyonu gerektirmeyen, tek
    # başına güvenilir metrik: client_send_ts - client_create_ts = mesajın
    # istemcide bant genişliği kısıtlaması yüzünden kuyrukta bekleme süresi.
    client_create_ts = Column(Float, nullable=True)  # olayın algılanıp kuyruğa girdiği an
    client_send_ts   = Column(Float, nullable=True)  # token-bucket bekleyişi bitip fiilen gönderildiği an

    istemci = relationship("Istemci", back_populates="loglar")

class KaraListe(Base):
    """Yasaklı uygulamalar ve hash'leri."""
    __tablename__ = "kara_liste"

    id = Column(Integer, primary_key=True, autoincrement=True)
    islem_adi = Column(String, nullable=True)
    hash_sha256 = Column(String, nullable=True, index=True)
    risk_puani = Column(Integer, default=50)
    aciklama = Column(String, nullable=True)
    priority_scope = Column(Integer, nullable=True)
    device_scope_id = Column(String, nullable=True)

    __table_args__ = (
        UniqueConstraint('hash_sha256', 'priority_scope', 'device_scope_id', name='uq_kara_liste_hash_scope'),
    )

class BeyazListe(Base):
    """Yönetici tarafından güvenli/izinli kabul edilen ve uç noktalara senkronize edilen uygulamalar."""
    __tablename__ = "beyaz_liste"

    id = Column(Integer, primary_key=True, autoincrement=True)
    islem_adi = Column(String, nullable=True)
    hash_sha256 = Column(String, nullable=False, index=True)
    aciklama = Column(String, nullable=True)
    istemci_id = Column(String, ForeignKey("istemciler.id"), nullable=True)
    priority_scope = Column(Integer, nullable=True)
    device_scope_id = Column(String, nullable=True)

    __table_args__ = (
        UniqueConstraint('hash_sha256', 'priority_scope', 'device_scope_id', name='uq_beyaz_liste_hash_scope'),
    )

class SistemOlaylari(Base):
    """Sunucu ve sistem genelindeki kritik olayların logları (DB kopması, recover, manuel komutlar vb.)."""
    __tablename__ = "sistem_olaylari"

    id = Column(Integer, primary_key=True, autoincrement=True)
    kategori = Column(String)  # GUVENLIK, DB, SISTEM, COOLDOWN, ADMIN
    olay_tipi = Column(String)  # RECOVER, DB_DISCONNECT, DB_RECOVERY, COOLDOWN_EXPIRED, MANUEL_KOMUT, OTOMATIK_AKSIYON
    mesaj = Column(String)
    istemci_id = Column(String, nullable=True)
    zaman_damgasi = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class IstemciSertifikasi(Base):
    """Cihaz X.509 sertifika metadata tablosu."""
    __tablename__ = "sertifikalar"

    id = Column(Integer, primary_key=True, autoincrement=True)
    istemci_id = Column(String, ForeignKey("istemciler.id"), nullable=False)
    serial_number = Column(String, unique=True, nullable=False)
    fingerprint = Column(String, unique=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=False)
    status = Column(String, default="ACTIVE") # ACTIVE, REVOKED, EXPIRED

    istemci = relationship("Istemci", backref="sertifikalar")


class OncelikPolitikalari(Base):
    """Her oncelik seviyesi (1-10) icin dinamik is kurallari (karantina sureleri, risk eslikleri, telemetri vb.).
    Sistemin tum karar mekanizmasi config.py yerine bu tablodan beslenir.
    10=En Kritik/Onemli, 1=En Dusuk/Standart cihaz.
    """
    __tablename__ = "oncelik_politikalari"

    id = Column(Integer, primary_key=True, autoincrement=True)
    priority_level = Column(Integer, unique=True, nullable=False, index=True)  # 1-10
    aciklama = Column(Text, default="")

    # Karantina ve Ceza Sureleri (saniye)
    restrict_duration_sec  = Column(Integer, default=1800)   # RESTRICT suresi
    isolate_duration_sec   = Column(Integer, default=900)    # ISOLATE suresi
    lockdown_duration_sec  = Column(Integer, default=600)    # LOCKDOWN suresi

    # Telemetri: Yuksek oncelikli cihazlar daha sik veri gonderir
    telemetry_interval_sec = Column(Integer, default=30)

    # Risk Eslikleri (0.0-100.0): Mevcut risk_engine.py hardcoded 50/80/90 bu tabloya tasindi
    risk_threshold_restrict  = Column(Float, default=55.0)
    risk_threshold_isolate   = Column(Float, default=80.0)
    risk_threshold_lockdown  = Column(Float, default=90.0)

    # Bant Genisligi (KB/s)
    min_bandwidth_kbps = Column(Integer, default=5)

    # Ozel Davranis Bayraklari
    ai_analysis_enabled  = Column(Boolean, default=True)   # AI analizi aktif mi?
    auto_isolate_exempt  = Column(Boolean, default=False)  # Otomatik ISOLATE/LOCKDOWN'dan muaf mi?


class SunucuAyarlari(Base):
    """Global sunucu ayarlari (tekil satir). id her zaman 1 olarak kalir.
    Bant genisligi optimizasyonu ve diger sunucu geneli parametreler burada tutulur.
    """
    __tablename__ = "sunucu_ayarlari"

    id = Column(Integer, primary_key=True, default=1)  # Her zaman 1
    global_max_bandwidth_kbps  = Column(Float, default=2048.0)   # KB/s toplam limit
    optimization_interval_sec  = Column(Integer, default=60)
    active_optimizer           = Column(String,  default="genetic")  # 'genetic' | 'proportional_fair'
    max_offline_queue_size     = Column(Integer, default=500)
    ai_api_key                 = Column(String, nullable=True)
    global_ai_enabled          = Column(Boolean, default=True)
    # YENİ: False iken RiskEngine risk skorunu/aksiyon kararını hesaplayıp
    # LogKaydi'ye yazmaya devam eder (analiz için), ama BLOCK_APP / RESTRICT /
    # ISOLATE / LOCKDOWN komutları istemciye GÖNDERİLMEZ ve cooldown/RECOVER
    # thread'i başlatılmaz. Bant genişliği algoritma karşılaştırma testinde
    # (3x3 matris) RESTRICT'in optimizer dışından fill_rate değiştirmesi veya
    # ISOLATE'in cihazı tamamen susturması veriyi kirletmesin diye eklendi.
    security_actions_enabled   = Column(Boolean, default=True)

# ======================= VERİTABANI BAĞLANTISI VE FALLBACK =======================

def _create_engine(db_url: str):
    if db_url.startswith("sqlite"):
        engine = create_engine(
            db_url,
            echo=False,
            connect_args={"check_same_thread": False, "timeout": 30.0}, # Multi-thread ve kilitlenmeyi önlemek icin timeout
        )
        # Windows Service altında çalışırken çoklu worker kilitlenmesini engellemek için WAL modunu aktif et
        with engine.connect() as conn:
            conn.execute(text("PRAGMA journal_mode=WAL;"))
        return engine
    return create_engine(
        db_url,
        echo=False,
        pool_size=10,
        max_overflow=5,
        pool_pre_ping=True,
        connect_args={
            "connect_timeout": _config.DB_CONNECT_TIMEOUT,
            "options": f"-c statement_timeout={_config.DB_STATEMENT_TIMEOUT_MS}"
        }
    )

def _validate_engine(engine) -> bool: # Veritabanına 'SELECT 1' sorgusu atarak bağlantının gerçekten aktif olup olmadığını test eder
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False

def init_db_connection():
    """PostgreSQL veritabanını dener, olmazsa SQLite'a düşer."""
    if DATABASE_URL.startswith("postgresql"):
        try:
            import psycopg2  # noqa: F401
        except ModuleNotFoundError:
            logger.warning("[DB] psycopg2 yuklu degil! SQLite yedek veritabanina geciliyor.")
            sqlite_engine = _create_engine(SQLITE_URL)
            return sqlite_engine, SQLITE_URL

    try:
        logger.info(f"[DB] Birincil veritabanina baglaniliyor: {DATABASE_URL}")
        primary_engine = _create_engine(DATABASE_URL)
        if _validate_engine(primary_engine):
            return primary_engine, DATABASE_URL
        else:
            raise ConnectionError("Birincil veritabanina baglanti dogrulamasi basarisiz oldu.")
    except Exception as e:
        logger.warning(f"[DB] Birincil veritabani hatasi ({e}). SQLite yedek veritabanina geciliyor: {SQLITE_URL}")
        sqlite_engine = _create_engine(SQLITE_URL)
        return sqlite_engine, SQLITE_URL

import threading
db_lock = threading.RLock()

# Veritabanı bağlantı motoru ve oturum yapılandırıcısı
engine, ACTIVE_DB_URL = init_db_connection()
_SessionMaker = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# SessionLocal health-check periyodu: her istekte SELECT 1 yerine
# en fazla bu aralıkta bir kontrol yapılır (saniye)
_DB_HEALTH_CHECK_INTERVAL = _config.DB_HEALTH_CHECK_INTERVAL
_last_db_health_check: float = 0.0

def SessionLocal():
    """Bağlantı koptuğunda otomatik fallback_to_sqlite() tetikleyen sarmalanmış Session üretici.
    PostgreSQL sağlık kontrolü en fazla _DB_HEALTH_CHECK_INTERVAL saniyede bir yapılır;
    her istekte SELECT 1 atmak yerine periyodik kontrol ile performans korunur."""
    global _last_db_health_check
    
    # Sadece birincil DB (PostgreSQL) aktifken ping atarız
    if ACTIVE_DB_URL != SQLITE_URL:
        now = time.time()
        if now - _last_db_health_check >= _config.DB_HEALTH_CHECK_INTERVAL:
            _last_db_health_check = now
            if not _validate_engine(engine):
                logger.warning("[DB] Birincil veritabanina ping atilamadi! SQLite yedek veritabanina geciliyor...")
                fallback_to_sqlite()
            
    return _SessionMaker()

def switch_db(new_url: str):
    """Veritabanı bağlantı motorunu dinamik olarak değiştirir (thread-safe)."""
    global engine, ACTIVE_DB_URL, _last_db_health_check
    with db_lock:
        if ACTIVE_DB_URL == new_url:
            return True
        logger.info(f"[DB] Veritabani motoru degistiriliyor: {new_url}")
        try:
            new_engine = _create_engine(new_url)
            with new_engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            
            engine = new_engine
            ACTIVE_DB_URL = new_url
            _SessionMaker.configure(bind=new_engine)
            # Geçiş sonrası health check timer'ı sıfırla:
            # Yeni DB bağlantısı kurulduğunda bir sonraki SessionLocal() çağrısı
            # anında doğrulama yapar (15s bekleme olmaz).
            _last_db_health_check = 0.0
            logger.info("[DB] Veritabani motoru basariyla degistirildi.")
            return True
        except Exception as e:
            logger.error(f"[DB] Veritabani motoru degistirilirken hata: {e}")
            return False


def fallback_to_sqlite():
    """Çalışma zamanında birincil DB koptuğunda SQLite'a geçiş yapar."""
    global ACTIVE_DB_URL
    if ACTIVE_DB_URL != SQLITE_URL:
        logger.warning(f"[DB-FALLBACK] Birincil veritabani koptu! SQLite yedegine geciliyor: {SQLITE_URL}")
        switch_db(SQLITE_URL)
        try:
            # Doğrudan _SessionMaker kullanarak kısırdöngü (recursion) oluşmasını engelle
            db = _SessionMaker()
            sys_event = SistemOlaylari(
                kategori="DB",
                olay_tipi="DB_DISCONNECT",
                mesaj=f"Birincil veritabani baglantisi koptu! SQLite yedek veritabanina gecildi."
            )
            db.add(sys_event)
            db.commit()
            db.close()
        except Exception as err:
            logger.error(f"[DB-FALLBACK] SQLite'a durum logu yazilamadi: {err}")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_tables():
    """Tabloları oluşturur, varsayılan kara liste verilerini ekler ve schema migration yapar."""
    # 1. Aktif veritabanındaki tabloları oluştur
    Base.metadata.create_all(bind=engine)
    logger.info("[DB] Aktif veritabanı tablolari basariyla olusturuldu.")

    # 2. SQLite yedek veritabanındaki tabloların da her durumda hazır olmasını sağla
    try:
        sqlite_fallback_engine = _create_engine(SQLITE_URL)
        Base.metadata.create_all(bind=sqlite_fallback_engine)
        logger.info("[DB] SQLite yedek veritabani tablolari doğrulandi/olusturuldu.")
        # SQLite için telemetry_interval migration'ı yap
        with sqlite_fallback_engine.connect() as sqlite_conn:
            try:
                sqlite_conn.execute(text("ALTER TABLE istemciler ADD COLUMN telemetry_interval INTEGER"))
                sqlite_conn.commit()
            except Exception:
                pass
    except Exception as e:
        logger.error(f"[DB] SQLite yedek tablolari hazirlanirken hata: {e}")

    # Schema Migration: Mevcut veritabanlarinda yeni kolonlari ALTER TABLE ile ekle
    _migration_stmts = [
        "ALTER TABLE istemciler ADD COLUMN telemetry_interval INTEGER",
        "ALTER TABLE istemciler ADD COLUMN pc_priority INTEGER DEFAULT 5",
        "ALTER TABLE kara_liste ADD COLUMN priority_scope INTEGER",
        "ALTER TABLE kara_liste ADD COLUMN device_scope_id TEXT",
        "ALTER TABLE beyaz_liste ADD COLUMN priority_scope INTEGER",
        "ALTER TABLE beyaz_liste ADD COLUMN device_scope_id TEXT",
        "ALTER TABLE sunucu_ayarlari ADD COLUMN ai_api_key TEXT",
        "ALTER TABLE sunucu_ayarlari ADD COLUMN global_ai_enabled BOOLEAN DEFAULT TRUE",
        "ALTER TABLE log_kayitlari ADD COLUMN client_create_ts FLOAT",
        "ALTER TABLE log_kayitlari ADD COLUMN client_send_ts FLOAT",
        "ALTER TABLE sunucu_ayarlari ADD COLUMN security_actions_enabled BOOLEAN DEFAULT TRUE",
    ]
    with engine.connect() as conn:
        for stmt in _migration_stmts:
            try:
                conn.execute(text(stmt))
                conn.commit()
                logger.info(f"[DB] Schema migration: {stmt.split('ADD COLUMN')[1].strip().split()[0]} kolonu eklendi.")
            except Exception:
                pass  # Kolon zaten varsa sessizce gec

        # SQLite/PostgreSQL UNIQUE Constraint Kaldirma Migration
        # SQLite'da tabloyu yeniden olusturarak UNIQUE kaldirabiliriz.
        try:
            # Sadece SQLite için (Eger SQLite ise)
            if SQLITE_URL in ACTIVE_DB_URL or SQLITE_URL in engine.url.render_as_string(hide_password=False):
                # KaraListe Migration
                conn.execute(text("CREATE TABLE IF NOT EXISTS kara_liste_new (id INTEGER PRIMARY KEY AUTOINCREMENT, islem_adi VARCHAR, hash_sha256 VARCHAR, risk_puani INTEGER, aciklama VARCHAR, priority_scope INTEGER, device_scope_id VARCHAR, CONSTRAINT uq_kara_liste_hash_scope UNIQUE (hash_sha256, priority_scope, device_scope_id))"))
                conn.execute(text("INSERT OR IGNORE INTO kara_liste_new (id, islem_adi, hash_sha256, risk_puani, aciklama, priority_scope, device_scope_id) SELECT id, islem_adi, hash_sha256, risk_puani, aciklama, priority_scope, device_scope_id FROM kara_liste"))
                conn.execute(text("DROP TABLE kara_liste"))
                conn.execute(text("ALTER TABLE kara_liste_new RENAME TO kara_liste"))
                
                # BeyazListe Migration
                conn.execute(text("CREATE TABLE IF NOT EXISTS beyaz_liste_new (id INTEGER PRIMARY KEY AUTOINCREMENT, islem_adi VARCHAR, hash_sha256 VARCHAR NOT NULL, aciklama VARCHAR, istemci_id VARCHAR, priority_scope INTEGER, device_scope_id VARCHAR, CONSTRAINT uq_beyaz_liste_hash_scope UNIQUE (hash_sha256, priority_scope, device_scope_id))"))
                conn.execute(text("INSERT OR IGNORE INTO beyaz_liste_new (id, islem_adi, hash_sha256, aciklama, istemci_id, priority_scope, device_scope_id) SELECT id, islem_adi, hash_sha256, aciklama, istemci_id, priority_scope, device_scope_id FROM beyaz_liste"))
                conn.execute(text("DROP TABLE beyaz_liste"))
                conn.execute(text("ALTER TABLE beyaz_liste_new RENAME TO beyaz_liste"))
                conn.commit()
                logger.info("[DB] SQLite Table recreate migration (multi-scope) yapildi.")
        except Exception as e:
            logger.error(f"[DB] Multi-Scope Migration hatasi: {e}")

    db = SessionLocal()
    try:
        default_blacklist = []
        
        for item in default_blacklist:
            exists = None
            if item.hash_sha256:
                exists = db.query(KaraListe).filter_by(hash_sha256=item.hash_sha256).first()
            if not exists and item.islem_adi:
                exists = db.query(KaraListe).filter_by(islem_adi=item.islem_adi).first()
                
            if not exists:
                db.add(item)
        db.commit()
        logger.info("[DB] Veritabani basariyla baslatildi.")

        pass

    except Exception as e:
        logger.error(f"[DB] Varsayilan veri eklenirken hata: {e}")
        db.rollback()
    finally:
        db.close()

    # ---- Oncelik Politikalari Seed Data ----
    db = SessionLocal()
    try:
        _seed_policies = [
            # priority | aciklama                    | restrict | isolate | lockdown | telemetry | r_restrict | r_isolate | r_lockdown | ai    | exempt
            (10, "Kritik Sunucu / BT Yoneticisi",   7200, 3600, 1800, 10, 75.0, 92.0, 97.0, True,  False),
            (9,  "Sunucu Odasi / Altyapi",           6000, 3000, 1500, 15, 72.0, 90.0, 95.0, True,  False),
            (8,  "Ust Duzey Yonetici",               4800, 2400, 1200, 15, 68.0, 87.0, 93.0, True,  False),
            (7,  "Bolum Muduru / Kidemli Kullanici", 3600, 1800,  900, 20, 65.0, 85.0, 92.0, True,  False),
            (6,  "Uzman Calisan",                    2700, 1350,  720, 25, 60.0, 82.0, 91.0, True,  False),
            (5,  "Standart Calisan",                 1800,  900,  600, 30, 55.0, 80.0, 90.0, True,  False),
            (4,  "Stajyer / Alt Duzey",              1200,  600,  360, 45, 48.0, 75.0, 88.0, True,  False),
            (3,  "Misafir / Gecici Hesap",            600,  300,  180, 60, 40.0, 70.0, 85.0, False, False),
            (2,  "Karantina / Gozlem Alti",           420,  180,   90, 90, 33.0, 65.0, 82.0, False, False),
            (1,  "Test / Izole Cihaz",                300,  120,   60,120, 25.0, 60.0, 80.0, False, False),
        ]
        for (lvl, acik, res, iso, lck, tel, rr, ri, rl, ai, exempt) in _seed_policies:
            if not db.query(OncelikPolitikalari).filter_by(priority_level=lvl).first():
                db.add(OncelikPolitikalari(
                    priority_level=lvl, aciklama=acik,
                    restrict_duration_sec=res, isolate_duration_sec=iso, lockdown_duration_sec=lck,
                    telemetry_interval_sec=tel,
                    risk_threshold_restrict=rr, risk_threshold_isolate=ri, risk_threshold_lockdown=rl,
                    ai_analysis_enabled=ai, auto_isolate_exempt=exempt
                ))
        db.commit()
        logger.info("[DB] Oncelik politikalari seed data yuklendi (10 seviye).")
    except Exception as e:
        logger.error(f"[DB] Oncelik politikalari seed data hatasi: {e}")
        db.rollback()
    finally:
        db.close()

    # ---- Sunucu Ayarlari Seed Data (tekil satir) ----
    db = SessionLocal()
    try:
        if not db.query(SunucuAyarlari).filter_by(id=1).first():
            db.add(SunucuAyarlari())
            db.commit()
            logger.info("[DB] Sunucu ayarlari varsayilan kaydi olusturuldu.")
    except Exception as e:
        logger.error(f"[DB] Sunucu ayarlari olusturulurken hata: {e}")
        db.rollback()
    finally:
        db.close()


if __name__ == "__main__":
    init_tables()