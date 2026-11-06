import os
from pathlib import Path

# .env dosyasını otomatik yükle (python-dotenv)
# Önce common/'ın bir üstü olan proje kökünü (Yaso_Deneme/) dene, bulamazsa bir üst daha bak.
try:
    from dotenv import load_dotenv
    import sys
    
    if getattr(sys, 'frozen', False):
        exe_dir = Path(sys.executable).parent
        possible_envs = [
            exe_dir / ".env",                                   # Next to exe (Production)
            exe_dir.parent.parent.parent / ".env",              # Yaso_Deneme/.env (when running from server/dist/NocSentinelServer)
            Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "NocSentinelServer" / ".env" # Persistent storage
        ]
        _env_file = None
        for p in possible_envs:
            if p.exists():
                _env_file = p
                break
        
        if not _env_file:
            _env_file = exe_dir / ".env" # Fallback so it doesn't crash
    else:
        _config_dir = Path(__file__).resolve().parent          # common/
        _project_root = _config_dir.parent                     # Yaso_Deneme/
        _env_file = _project_root / ".env"
        
    if _env_file and _env_file.exists():
        load_dotenv(dotenv_path=str(_env_file))
    else:
        load_dotenv()   # Varsayılan davranış: çalışma dizininden ara
except ImportError:
    pass  # python-dotenv yüklü değilse ortam değişkenlerini doğrudan kullan

# =============================================================================
# ORTAK AYARLAR — Hem istemci hem sunucu tarafında kullanılır
# Gelecekte ayrılacaksa: client_config.py ve server_config.py'ye taşıyın.
# =============================================================================

# [ORTAK] MQTT Broker Bağlantısı
# TLS aktifse MQTT_PORT otomatik olarak SECURE_MQTT_PORT (8883) ile ezilir.
MQTT_BROKER = os.environ.get("MQTT_BROKER", "127.0.0.1")
MQTT_PORT = int(os.environ.get("MQTT_PORT", 8883))    # Varsayılan: TLS portu
SECURE_MQTT_PORT = 8883

# [ORTAK] Kriptografi & Güvenlik
# UYARI: Ortak token'ları asla kaynak koda yazmayın. .env dosyasından okuyun.
PRODUCTION = os.environ.get("PRODUCTION", "false").lower() == "true"
REGISTRATION_TOKEN = os.environ.get("REGISTRATION_TOKEN", "")
if not REGISTRATION_TOKEN:
    if PRODUCTION:
        raise ValueError("[GUVENLIK HATA] Uretim modunda REGISTRATION_TOKEN ortam degiskeni tanimlanmak zorundadir!")
    else:
        REGISTRATION_TOKEN = "SENTINEL_BOOTSTRAP_TOKEN_2026"

# [ORTAK] Varsayilan Donanim Izleme Sikligi (Saniye) - SADECE FALLBACK
# Gercek deger artik veritabanindaki OncelikPolitikalari.telemetry_interval_sec'den okunur.
# Bu deger sadece DB'ye erisim olmayan durumlarda veya istemci baslangicinda kullanilir.
DEFAULT_TELEMETRY_INTERVAL = 30  # Fallback degeri

# =============================================================================
# SUNUCU TARAFI AYARLARI — Yalnızca receiver_server.py ve workers.py kullanır
# Gelecekte ayrılacaksa: server_config.py'ye taşıyın.
# =============================================================================

# [SUNUCU] Redis Kuyruk Bağlantısı
REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
REDIS_DB = int(os.environ.get("REDIS_DB", 0))
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", "")
REDIS_LOG_KEY = "noc_sentinel_priority_log_queue"
REDIS_TELEMETRY_KEY = "noc_sentinel_telemetry_queue"

# [SUNUCU] Yapay Zeka ile Akıllı Log Denetimi
# AI anahtarı ve aktiflik durumu sadece sunucuda bulunur.
USE_AI_ANALYSIS = os.environ.get("USE_AI_ANALYSIS", "true").lower() == "true"
AI_API_KEY = os.environ.get("AI_API_KEY", "")
AI_API_BASE = os.environ.get("AI_API_BASE", "https://api.deepseek.com")    # .env'den degistirilebilir (OpenAI uyumlu herhangi bir API)
AI_API_MODEL = os.environ.get("AI_API_MODEL", "deepseek-chat")              # .env'den degistirilebilir

# [SUNUCU] Veritabanı Bağlantı ve Sağlık Kontrol Süreleri
DB_HEALTH_CHECK_INTERVAL = int(os.environ.get("DB_HEALTH_CHECK_INTERVAL", 15))   # SessionLocal sağlık kontrol aralığı (sn)
DB_CONNECT_TIMEOUT = int(os.environ.get("DB_CONNECT_TIMEOUT", 3))                # PostgreSQL bağlantı zaman aşımı (sn)
DB_STATEMENT_TIMEOUT_MS = int(os.environ.get("DB_STATEMENT_TIMEOUT_MS", 3000))   # PostgreSQL sorgu zaman aşımı (ms)

# [SUNUCU] Redis Bağlantı Kontrol Süreleri
REDIS_RECONNECT_INTERVAL = int(os.environ.get("REDIS_RECONNECT_INTERVAL", 10))   # Redis yeniden bağlantı deneme aralığı (sn)
REDIS_SOCKET_TIMEOUT = int(os.environ.get("REDIS_SOCKET_TIMEOUT", 3))            # Redis soket zaman aşımı (sn)

# [SUNUCU] Worker Döngü Süreleri
TRAFFIC_REPORT_INTERVAL = int(os.environ.get("TRAFFIC_REPORT_INTERVAL", 5))      # Trafik raporlama sıklığı (sn)
AGING_INTERVAL = int(os.environ.get("AGING_INTERVAL", 10))                       # Log yaşlandırma döngüsü sıklığı (sn)
