import os
import sys
import time
import datetime
import threading
import logging
import multiprocessing
import paho.mqtt.client as mqtt

# Modüler Bileşenlerin Import Edilmesi (Önce ortak common/ ve server/ yollarını ekle)
server_dir = os.path.dirname(os.path.abspath(__file__))
common_dir = os.path.join(os.path.dirname(server_dir), "common")
sys.path.insert(0, server_dir)
if os.path.exists(common_dir):
    sys.path.insert(0, common_dir)

import path_helper
logger = path_helper.setup_global_logging()
logger.name = "ReceiverServer"

import database
from database import SessionLocal, init_tables, Istemci, IstemciSertifikasi
from crypto_helper import CryptoHelper
from registry import CallbackRegistry
from thread_supervisor import supervise_thread
import app_config as config

# Sunucu alt bileşenlerinin import edilmesi
from token_bucket import TokenBucket
from workers import (
    redis_mgr, r, stats, get_token_bucket,
    queue_worker, telemetry_worker, db_recovery_worker,
    aging_worker, throughput_reporter, optimization_worker,
    redis_reconnect_worker, retention_worker
)

# Log yapılandırması artık path_helper.setup_global_logging() içinde hallediliyor
# logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# logger = logging.getLogger("ReceiverServer")

# ======================= AYARLAR =======================
MQTT_BROKER = config.MQTT_BROKER
MQTT_PORT = config.MQTT_PORT
MQTT_CLIENT_ID = "noc_sentinel_receiver_server"

from path_helper import get_persistent_dir
CERTS_DIR = get_persistent_dir("certs")


CA_CERT = os.path.join(CERTS_DIR, "ca.crt")
CLIENT_CERT = os.path.join(CERTS_DIR, "client.crt")
CLIENT_KEY = os.path.join(CERTS_DIR, "client.key")

WHITELIST_MODE = os.environ.get("WHITELIST_MODE", "false").lower() == "true"

if WHITELIST_MODE:
    logger.info("[KONFIGÜRASYON] WHITELIST_MODE=True: Yalnizca onaylanmis PC'lerden veri kabul edilecek.")
else:
    logger.warning("[KONFIGÜRASYON] WHITELIST_MODE=False: Tum baglanan cihazlardan veri kabul ediliyor (TEST MODU).")

# Sunucu küresel giriş hız sınırı (Max 2 MB/sn başlangıç değeri, dinamik güncellenebilir)
GLOBAL_INGRESS_BUCKET = TokenBucket(capacity=2 * 1024 * 1024, fill_rate=2 * 1024 * 1024)
mqtt_client = None

# Sunucu beyaz liste senkronizasyon takip havuzu
SYNCED_CLIENTS = set()
synced_clients_lock = threading.Lock()

def send_whitelist_to_client(pc_name: str):
    logger.info(f"[BEYAZLISTE] {pc_name} icin beyaz liste senkronizasyonu baslatildi.")
    db = SessionLocal()
    try:
        from database import BeyazListe, Istemci
        whitelist_records = db.query(BeyazListe).filter((BeyazListe.istemci_id == pc_name) | (BeyazListe.istemci_id == None)).all()
        hashes_list = [record.hash_sha256 for record in whitelist_records]
        
        payload = {
            "action": "SYNC_ALLOWED_HASHES",
            "hashes": hashes_list
        }
        
        # Sıkıştır ve şifrele
        encrypted_payload = CryptoHelper.encrypt_and_compress(payload)
        
        # MQTT ile yayınla
        control_topic = f"network/control/{pc_name}"
        res = mqtt_client.publish(control_topic, encrypted_payload, qos=1)
        res.wait_for_publish(timeout=3)
        logger.info(f"[BEYAZLISTE] {pc_name} icin {len(hashes_list)} adet allowed hash basariyla gonderildi.")

        # Cihaza kayıtlı özel telemetri aralığını gönder
        device = db.query(Istemci).filter_by(id=pc_name).first()
        interval = device.telemetry_interval if (device and device.telemetry_interval) else config.DEFAULT_TELEMETRY_INTERVAL
        cmd = {"action": "UPDATE_TELEMETRY_INTERVAL", "interval": interval}
        encrypted_cmd = CryptoHelper.encrypt_and_compress(cmd)
        mqtt_client.publish(control_topic, encrypted_cmd, qos=1)
        logger.info(f"[TELEMETRI] {pc_name} icin baslangic telemetri araligi gonderildi: {interval}s")

    except Exception as e:
        logger.error(f"[BEYAZLISTE] {pc_name} icin senkronizasyon hatasi: {e}")
        with synced_clients_lock:
            SYNCED_CLIENTS.discard(pc_name)
    finally:
        db.close()

# Fonksiyon tanımlandıktan hemen sonra registry'e kaydet;
# böylece admin_api.py bu fonksiyonu receiver_server import etmeden çağırabilir.
CallbackRegistry.register("send_whitelist", send_whitelist_to_client)

# mqtt_client nesnesine erişimi registry üzerinden sun;
# admin_api.py bu fonksiyon aracılığıyla mqtt_client'a ulaşır, doğrudan import gerektirmez.
def _get_mqtt_client():
    return mqtt_client

CallbackRegistry.register("get_mqtt_client", _get_mqtt_client)

# RAM önbellek: yüksek trafik altında veritabanı kilitlenmelerini önler
CLIENT_CACHE_TTL = 10.0  # 10 saniye önbellek süresi
_client_info_cache = {}
_client_info_lock = threading.Lock()

def invalidate_client_cache(pc_name: str = None):
    with _client_info_lock:
        if pc_name:
            _client_info_cache.pop(pc_name, None)
        else:
            _client_info_cache.clear()

def get_client_info_cached(pc_name: str):
    """İstemci yetkilendirme, aktif sertifika ve öncelik bilgilerini RAM'de saklar.
    Her gelen pakette DB sorgusu yapılmasını engelleyerek sunucu kilitlenmesini çözer.
    """
    now = time.time()
    with _client_info_lock:
        if pc_name in _client_info_cache:
            entry = _client_info_cache[pc_name]
            if now - entry["timestamp"] < CLIENT_CACHE_TTL:
                return entry["allowed"], entry["risk_score"], entry["pc_priority"]

    allowed = True
    risk_score = 0.0
    pc_priority = 5.0

    try:
        db = SessionLocal()
        try:
            db_client = db.query(Istemci).filter_by(id=pc_name).first()
            if WHITELIST_MODE and db_client is None:
                allowed = False
            else:
                active_cert = db.query(IstemciSertifikasi).filter_by(istemci_id=pc_name, status="ACTIVE").first()
                if not active_cert:
                    allowed = False
                else:
                    allowed = True
                    risk_score = db_client.mevcut_puan if db_client else 0.0
                    pc_priority = float(db_client.pc_priority) if (db_client and hasattr(db_client, 'pc_priority')) else 5.0
        finally:
            db.close()
    except Exception as db_err:
        short_err = str(db_err).split('\n')[0]
        logger.warning(f"[SUNUCU] Whitelist/Cert kontrolunde DB hatasi, SQLite fallback deneniyor: {short_err}")
        try:
            database.fallback_to_sqlite()
            db = database.SessionLocal()
            try:
                db_client = db.query(Istemci).filter_by(id=pc_name).first()
                active_cert_fb = db.query(IstemciSertifikasi).filter_by(istemci_id=pc_name, status="ACTIVE").first()
                if not active_cert_fb:
                    allowed = False
                else:
                    allowed = True
                    if WHITELIST_MODE and db_client is None:
                        risk_score = 0.0
                        pc_priority = 5.0
                    else:
                        risk_score = db_client.mevcut_puan if db_client else 0.0
                        pc_priority = float(db_client.pc_priority) if (db_client and hasattr(db_client, 'pc_priority')) else 5.0
            finally:
                db.close()
        except Exception as fb_err:
            short_fb_err = str(fb_err).split('\n')[0]
            logger.error(f"[SUNUCU] SQLite fallback veritabanina da baglanilamadi: {short_fb_err}")
            allowed = True
            risk_score = 0.0
            pc_priority = 5.0

    with _client_info_lock:
        _client_info_cache[pc_name] = {
            "timestamp": now,
            "allowed": allowed,
            "risk_score": risk_score,
            "pc_priority": pc_priority
        }

    return allowed, risk_score, pc_priority

# ======================= MQTT CALLBACKS =======================

def on_connect(client, userdata, flags, reason_code, properties=None):
    try:
        if reason_code == 0:
            logger.info(f"[MQTT] Broker'a baglanildi ({MQTT_BROKER}:{MQTT_PORT})")
            client.subscribe("network/logs/+", qos=1)
            client.subscribe("network/telemetry/+", qos=1)
            client.subscribe("network/client/startup/+", qos=1)
            client.subscribe("network/client/processes/+", qos=1)
            # Sunucu aktif olduğunu duyurur (retained)
            client.publish("network/server/status", "online", qos=1, retain=True)
            logger.info("[MQTT] Sunucu durum kanali 'online' olarak gonderildi.")
        else:
            logger.error(f"[MQTT] Baglanti hatasi, kod: {reason_code}")
    except Exception as e:
        logger.error(f"[MQTT] on_connect callback sirasinda kritik hata: {e}", exc_info=True)

def on_message(client, userdata, msg):
    try:
        packet_size = len(msg.payload)

        # Telemetri ve istemci durum paketleri (heartbeat) bant genişliği limitine takılmamalıdır!
        # Aksi takdirde yoğun log trafiğinde telemetri paketleri drop edilir ve cihazlar "Offline" görünür.
        is_telemetry_or_control = msg.topic.startswith("network/telemetry/") or msg.topic.startswith("network/client/")

        # Küresel Bant Genişliği Hız Sınırı Kontrolü (Yalnızca log trafiği için)
        if not is_telemetry_or_control and not GLOBAL_INGRESS_BUCKET.consume(packet_size):
            if packet_size <= 512:
                logger.debug(f"[LIMIT] Kucuk kontrol paketi ({packet_size} byte) limit bypass ile isleniyor.")
            else:
                logger.warning(f"[LIMIT] Kuresel sunucu limit asimi! {packet_size} byte DROP edildi.")
                with stats.lock:
                    stats.dropped_packets += 1
                return
            
        hex_preview = msg.payload[:15].hex()
        logger.info(f"[PAKET] Sifrelenmis paket alindi | Boyut: {packet_size} byte | Ilk15Byte(Hex): {hex_preview}")

        try:
            decrypted_payload = CryptoHelper.decrypt_and_decompress(msg.payload)
        except Exception as crypto_err:
            logger.warning(
                f"[KRIPTO] Sifresi cozulemeyen paket DROP edildi! "
                f"(Yanlis AES anahtari veya bozuk veri) Hata: {crypto_err}"
            )
            with stats.lock:
                stats.dropped_packets += 1
            return

        pc_name = decrypted_payload.get("pc_name", "Unknown_PC")

        # Startup Handshake Bildirimi (Seçenek 2: Sunucu Canlılık Bildirimi)
        if msg.topic.startswith("network/client/startup/"):
            logger.info(f"[AJAN-STARTUP] {pc_name} baslangic el sikismasi alindi. Senkronizasyon durumu havuzdan silindi.")
            with synced_clients_lock:
                SYNCED_CLIENTS.discard(pc_name)
            try:
                client.publish("network/server/status", "online", qos=1, retain=True)
            except Exception as e:
                logger.error(f"[MQTT] Startup el sikisma cevabi gonderilemedi: {e}")
            return

        # 1. KİMLİK DOĞRULAMA & SPOOFING KORUMASI
        topic_parts = msg.topic.split('/')
        if len(topic_parts) >= 3:
            pc_name_from_topic = topic_parts[-1]
            if pc_name_from_topic != pc_name:
                logger.error(
                    f"[SPOOFING] Kimlik sahteciligi girisimi engellendi! "
                    f"Topic PC: '{pc_name_from_topic}' | Paket PC: '{pc_name}' | Veri DROP edildi."
                )
                with stats.lock:
                    stats.dropped_packets += 1
                return

        # 2. WHITELIST VE SERTİFİKA KONTROLÜ (RAM Önbellek Korumalı)
        allowed, risk_score, pc_priority_db = get_client_info_cached(pc_name)
        if not allowed:
            logger.warning(f"[GUVENLIK/WHITELIST] Kayit disi veya sertifikasi pasif cihaz reddedildi! PC: '{pc_name}' — Veri DROP edildi.")
            with stats.lock:
                stats.dropped_packets += 1
            return

        # Cihaz bazında ilk veri alımında beyaz liste senkronizasyonu tetikle
        with synced_clients_lock:
            if pc_name not in SYNCED_CLIENTS:
                SYNCED_CLIENTS.add(pc_name)
                threading.Thread(target=send_whitelist_to_client, args=(pc_name,), daemon=True).start()

        # 3. İstemci Başına Jeton Kovası Kontrolü (Dinamik Optimizasyon Limitlerine Duyarlı)
        bucket = get_token_bucket(pc_name)
        if not bucket.consume(packet_size, risk_score):
            effective_rate = bucket.fill_rate * max(0.0, 1.0 - (risk_score / 100.0))
            logger.warning(
                f"[LIMIT] Hiz siniri asildi! {pc_name} | Paket: {packet_size} B | "
                f"Risk: {risk_score:.1f} | Kova Jeton: {bucket.tokens:.1f}/{bucket.capacity:.0f} B | "
                f"Etkin Dolum: {effective_rate:.1f} B/s | DROP edildi."
            )
            with stats.lock:
                stats.dropped_packets += 1
            return

        with stats.lock:
            stats.total_bytes += packet_size

        # 4. Verileri Uygun Kuyruğa İt
        import msgpack
        if msg.topic.startswith("network/logs/"):
            packed_log = msgpack.packb(decrypted_payload)
            # RAM önbellekten alınan cihaz önceliğini kullan (DB kilitlenmesini engeller)
            log_priority = float(decrypted_payload.get("log_priority", 5))
            ai_evaluated = decrypted_payload.get("ai_evaluated", False)

            # zset_score her durumda pc_priority * log_priority çarpımı ile hesaplanır
            zset_score = -(pc_priority_db * log_priority)

            _r = redis_mgr.get()
            try:
                _r.zadd(config.REDIS_LOG_KEY, {packed_log: zset_score})
            except Exception as redis_err:
                try:
                    import redis as _redis_lib
                    if isinstance(redis_err, (_redis_lib.ConnectionError, _redis_lib.TimeoutError,
                                              ConnectionRefusedError, OSError)):
                        redis_mgr.mark_failed()
                        # Fallback'e yaz (mark_failed yeni fallback kuyruğu oluşturdu)
                        redis_mgr.get().zadd(config.REDIS_LOG_KEY, {packed_log: zset_score})
                    else:
                        logger.error(f"[KUYRUK] Redis zadd hatasi: {redis_err}")
                except ImportError:
                    redis_mgr.mark_failed()
                    redis_mgr.get().zadd(config.REDIS_LOG_KEY, {packed_log: zset_score})
            logger.debug(f"[KUYRUK] Log eklendi | PC={pc_name} | AImod={ai_evaluated} | ZSETskor={zset_score:.1f}")


        elif msg.topic.startswith("network/client/processes/"):
            # Istemciden surec listesi yaniti geldi. Redis'e JSON formatinda atalim.
            try:
                import json
                _r = redis_mgr.get()
                redis_key = f"process_list:{pc_name}"
                # Gelen paket zaten dict, JSON'a cevir ve 60 sn expire ver
                _r.setex(redis_key, 60, json.dumps(decrypted_payload.get("processes", [])))
                logger.info(f"[SURECLER] {pc_name} surec listesi alindi ve Redis'e kaydedildi.")
            except Exception as e:
                logger.error(f"[SURECLER] Surec listesi kaydedilirken hata: {e}")

        elif msg.topic.startswith("network/telemetry/"):
            packed_tel = msgpack.packb(decrypted_payload)
            try:
                redis_mgr.get().lpush(config.REDIS_TELEMETRY_KEY, packed_tel)
            except Exception as redis_tel_err:
                try:
                    import redis as _redis_lib
                    if isinstance(redis_tel_err, (_redis_lib.ConnectionError, _redis_lib.TimeoutError,
                                                  ConnectionRefusedError, OSError)):
                        redis_mgr.mark_failed()
                        redis_mgr.get().lpush(config.REDIS_TELEMETRY_KEY, packed_tel)
                    else:
                        logger.error(f"[TELEMETRI] Redis lpush hatasi: {redis_tel_err}")
                except ImportError:
                    redis_mgr.mark_failed()
                    redis_mgr.get().lpush(config.REDIS_TELEMETRY_KEY, packed_tel)

    except Exception as e:
        logger.error(f"Mesaj islenirken beklenmedik hata: {e}")

def check_and_generate_certificates():
    """Kritik sertifika dosyaları eksikse otomatik olarak generate_certs.py'yi tetikler."""
    required_files = [
        CA_CERT, 
        CLIENT_CERT, 
        CLIENT_KEY,
        os.path.join(CERTS_DIR, "ca.key"),
        os.path.join(CERTS_DIR, "server.crt"),
        os.path.join(CERTS_DIR, "server.key")
    ]
    missing = [f for f in required_files if not os.path.exists(f)]
    if missing:
        logger.warning(f"[TLS] Eksik sertifika dosyalari tespit edildi: {[os.path.basename(m) for m in missing]}")
        logger.info("[TLS] Sertifikalar otomatik olarak yeniden uretiliyor...")
        try:
            # sys.path'e certs dizinini ekle ki import edebilelim (Exe içindeyken _MEIPASS, normalde üst klasör)
            import sys
            import importlib
            
            # certs modülünün yerini bul (Exe içindeyken CERTS_DIR)
            certs_parent = os.path.dirname(CERTS_DIR)
            if certs_parent not in sys.path:
                sys.path.insert(0, certs_parent)
                
            # O anki çalışma dizinini certs klasörü yap ki dosyalar oraya kaydedilsin
            old_cwd = os.getcwd()
            os.chdir(CERTS_DIR)
            
            from certs import generate_certs
            
            generate_certs.generate_default_certs(target_dir=CERTS_DIR)
            
            os.chdir(old_cwd)
            logger.info(f"[TLS] Sertifikalar basariyla dinamik IP algilanarak '{CERTS_DIR}' altinda otomatik uretildi.")
        except Exception as e:
            logger.critical(f"[TLS] Sertifika otomatik uretimi sirasinda hata: {e}")

def generate_mosquitto_conf():
    """ProgramData altında Mosquitto konfigürasyonunu oluşturur (Docker için)"""
    try:
        from path_helper import get_persistent_dir
        config_dir = get_persistent_dir("config")
        conf_path = os.path.join(config_dir, "mosquitto.conf")
        
        conf_content = """# =================================================================
# Mosquitto Broker TLS/SSL Configuration (NocSentinel)
# =================================================================

# 1. Şifresiz Standart MQTT Portu (Yalnizca dahili/localhost kullanimi)
#    receiver_server.py bu porta localhost uzerinden baglanir.
#    Dis agdan sertifikasiz baglantiya izin vermemek icin 127.0.0.1 ile kisitlandi.
listener 1883 127.0.0.1
allow_anonymous true

# 2. Şifreli SSL/TLS Güvenli MQTT Portu (Mutual TLS - mTLS)
listener 8883 0.0.0.0
cafile /mosquitto/config/certs/ca.crt
certfile /mosquitto/config/certs/server.crt
keyfile /mosquitto/config/certs/server.key

# İstemcilerin de geçerli bir istemci sertifikası (client.crt) sunmasını zorunlu kıl
require_certificate true

# Sertifikadaki Common Name (CN) alanını istemci adı (username) olarak kullan (Kimlik doğrulama için)
use_identity_as_username true
"""
        with open(conf_path, "w", encoding="utf-8") as f:
            f.write(conf_content)
        logger.info(f"[MOSQUITTO] Docker icin mosquitto.conf olusturuldu: {conf_path}")
    except Exception as e:
        logger.error(f"[MOSQUITTO] mosquitto.conf olusturulamadi: {e}")

# ======================= ANA GİRİŞ NOKTASI =======================

def main():
    global mqtt_client, MQTT_PORT
    
    # Eksik sertifikaları otomatik tamamla (Self-Healing)
    check_and_generate_certificates()
    
    # Docker konteynerleri için config dosyasını programdata içine yansıt
    generate_mosquitto_conf()
    
    # SQLite/PostgreSQL tablolarını ilklendir
    init_tables()
    
    # Oncelik politikalarini RAM onbellegine yukle (Risk Engine icin)
    from risk_engine import load_policy_cache
    load_policy_cache()
    
    mqtt_client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id=MQTT_CLIENT_ID,
        clean_session=True
    )
    mqtt_client.will_set(
        topic="network/server/status",
        payload="offline",
        qos=1,
        retain=True
    )
    mqtt_client.on_connect = on_connect
    mqtt_client.on_message = on_message
    
    use_tls = (config.MQTT_PORT == config.SECURE_MQTT_PORT or config.MQTT_PORT == 8883)
    if use_tls:
        if os.path.exists(CA_CERT) and os.path.exists(CLIENT_CERT) and os.path.exists(CLIENT_KEY):
            try:
                mqtt_client.tls_set(
                    ca_certs=CA_CERT,
                    certfile=CLIENT_CERT,
                    keyfile=CLIENT_KEY
                )
                _is_dev = os.environ.get("NOC_ENV", "production").lower() == "development"
                mqtt_client.tls_insecure_set(_is_dev)
                if _is_dev:
                    logger.warning("[TLS] UYARI: TLS hostname dogrulamasi KAPALI (development modu). Uretimde NOC_ENV=production yapin.")
                else:
                    logger.info("[TLS] Hostname dogrulamasi AKTIF (production modu).")
                MQTT_PORT = config.SECURE_MQTT_PORT
                logger.info(f"[TLS] Sunucu SSL/TLS haberlesme aktif edildi. Guvenli port {MQTT_PORT}'e gecildi.")
            except Exception as tls_err:
                logger.critical(f"[TLS] Sunucu TLS ayarlanirken kritik hata: {tls_err}")
                sys.exit(1)
        else:
            logger.critical("[TLS] Kritik Hata: SSL/TLS sertifikalari bulunamadi! Sunucu durduruluyor.")
            sys.exit(1)
    else:
        MQTT_PORT = config.MQTT_PORT
        logger.info(f"[MQTT] SSL/TLS devre disi (Port: {MQTT_PORT}). Standart MQTT baglantisi kullaniliyor.")

    mqtt_client.reconnect_delay_set(min_delay=1, max_delay=30)
    try:
        logger.info(f"[MQTT] Broker'a asenkron baglaniliyor: {MQTT_BROKER}:{MQTT_PORT}")
        mqtt_client.connect_async(MQTT_BROKER, MQTT_PORT, keepalive=60)
        mqtt_client.loop_start()
    except Exception as conn_err:
        logger.error(f"[MQTT] Baglanti baslatma hatasi: {conn_err}. Arka planda tekrar denenecek.")

    # Paralel çalışan alt thread'leri başlat (Supervisor ile — çökme durumunda otomatik yeniden başlar)
    num_workers = max(2, min(os.cpu_count() or 4, 8))
    logger.info(f"[WORKER] {num_workers} adet dinamik QueueWorker thread'i baslatiliyor (CPU Çekirdek Sayisi: {os.cpu_count()}).")
    for i in range(num_workers):
        supervise_thread(queue_worker, args=(mqtt_client,), name=f"QueueWorker-{i+1}")
    supervise_thread(telemetry_worker, name="TelemetryWorker")
    supervise_thread(throughput_reporter, name="ThroughputReporter")
    supervise_thread(db_recovery_worker, name="DbRecoveryWorker")
    supervise_thread(aging_worker, name="AgingWorker")
    supervise_thread(optimization_worker, args=(mqtt_client,), name="OptimizationWorker")
    supervise_thread(redis_reconnect_worker, name="RedisReconnectWorker")
    supervise_thread(retention_worker, name="RetentionWorker")
    
    # Admin REST API'sini başlat
    try:
        from admin_api import start_admin_api
        threading.Thread(target=start_admin_api, daemon=True).start()
        logger.info("[ADMIN-API] Admin REST API 8000 portunda baslatildi.")
    except Exception as api_err:
        logger.error(f"[ADMIN-API] Baslatma hatasi: {api_err}")

    logger.info("[SUNUCU] Alici Sunucu ve Otomatik Siber Savunma Sistemi Yayinda.")
    try:
        while not getattr(sys, 'svc_stop_flag', False):
            time.sleep(5)
            try:
                if mqtt_client:
                    mqtt_client.publish("network/server/status", "online", qos=1, retain=True)
            except Exception as publish_err:
                logger.debug(f"[MQTT] Periyodik durum yayinlama hatasi: {publish_err}")
    except KeyboardInterrupt:
        pass

    logger.info("[SUNUCU] Sunucu kapatiliyor...")
    try:
        mqtt_client.publish("network/server/status", "offline", qos=1, retain=True).wait_for_publish(timeout=2)
    except Exception as e:
        logger.error(f"[SUNUCU] Durum kapatma mesaji gonderilemedi: {e}")
    mqtt_client.loop_stop()

if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    main()
