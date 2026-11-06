import os
import sys
import time
import queue
import uuid
import socket
import hashlib
import logging
import threading
import subprocess
import psutil
import paho.mqtt.client as mqtt
import ctypes


# Modüler Şifreleme Import (Önce ortak common/ klasörünü ara, yoksa yereli dene)
from utils.path_helper import get_base_dir
base_dir = get_base_dir()
common_path = os.path.join(os.path.dirname(base_dir), "common")
if os.path.exists(common_path):
    sys.path.insert(0, common_path)

from crypto_helper import CryptoHelper
from thread_supervisor import supervise_thread
import app_config as config

# İstemci alt bileşenlerinin import edilmesi
from utils.token_bucket import TokenBucket
from database import init_offline_db, save_log_offline, send_offline_logs
from monitors import system_monitor, event_log_monitor, telemetry_sender, update_hash_cache

try:
    import certificate_manager
    CERT_MANAGER_AVAILABLE = True
except ImportError:
    CERT_MANAGER_AVAILABLE = False

handlers = []
if sys.stdout is not None:
    handlers.append(logging.StreamHandler(sys.stdout))

if handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers
    )
else:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.NullHandler()]
    )
logger = logging.getLogger("SenderAgent")

# ======================= AYARLAR =======================
MQTT_BROKER = config.MQTT_BROKER
MQTT_PORT = config.MQTT_PORT

# Cihaz kimliğini hostname + MAC adresinden dinamik olarak oluştur.
# Bu sayede exe farklı cihazlara dağıtıldığında hiçbir manuel konfigürasyon gerekmez;
# sunucu cihazları isim çakışması olmaksızın birbirinden ayırt edebilir.
def _build_device_id() -> str:
    """Bilgisayar adı + MAC adresinden eşsiz bir cihaz kimliği üretir.
    Örn: DESKTOP-AB12_0A1B2C3D4E5F
    """
    try:
        hostname = socket.gethostname().upper().replace(" ", "-")[:15]  # 15 karakter sınırı
        mac_int  = uuid.getnode()                                        # 48-bit MAC int
        mac_hex  = f"{mac_int:012X}"                                     # 12 karakter hex
        return f"{hostname}_{mac_hex}"
    except Exception:
        # Fallback: yalnızca MAC hex kullan
        return f"CLIENT_{uuid.getnode():012X}"

PC_NAME = _build_device_id()
logger_pre = logging.getLogger("SenderAgent")
logger_pre.info(f"[KIMLIK] Cihaz kimliği dinamik olarak belirlendi: {PC_NAME}")

MQTT_CLIENT_ID = f"noc_sentinel_sender_{PC_NAME}"

# Öncelik — Sunucu tarafından UPDATE_PRIORITY MQTT komutu ile anlık güncellenebilir.
# Varsayılan değer 5 (orta öncelik). Hard-coded değil.
PC_PRIORITY = 5
_pc_priority_lock = threading.Lock()

def get_pc_priority() -> int:
    with _pc_priority_lock:
        return PC_PRIORITY

# Dinamik Telemetri Sıklığı Ayarları
TELEMETRY_INTERVAL = config.DEFAULT_TELEMETRY_INTERVAL
_telemetry_interval_lock = threading.Lock()

def get_telemetry_interval():
    with _telemetry_interval_lock:
        return TELEMETRY_INTERVAL

# Sertifika Yolları (Güvenli ProgramData Klasörü)
from utils.path_helper import get_data_dir
data_dir = get_data_dir()
CERTS_DIR = os.path.join(data_dir, "certs")

CA_CERT = os.path.join(CERTS_DIR, "ca.crt")
SPECIFIC_CERT = os.path.join(CERTS_DIR, f"client_{PC_NAME}.crt")
SPECIFIC_KEY = os.path.join(CERTS_DIR, f"client_{PC_NAME}.key")

def get_admin_api_url(action_name: str, exit_on_error: bool = False) -> str:
    """Üretim ortamında HTTPS bağlantısını zorunlu kılan ve Admin API adresini dönen yardımcı fonksiyon."""
    default_url = f"http://{config.MQTT_BROKER}:8000"
    url = os.environ.get("ADMIN_API_URL", default_url)
    if getattr(config, "PRODUCTION", False) and url.startswith("http://"):
        msg = f"[GUVENLIK HATA] Uretim modunda Admin API {action_name} baglantisi HTTPS olmak zorundadir!"
        logger.critical(msg)
        if exit_on_error:
            import sys
            sys.exit(1)
        else:
            raise ValueError(msg)
    return url

def init_agent_certificates():
    if not CERT_MANAGER_AVAILABLE:
        logger.warning("[TLS] certificate_manager modulu yuklenemedi. Geriye donuk uyumluluk moduna geciliyor.")
        return
        
    SERVER_HTTPS_URL = get_admin_api_url("kayit", exit_on_error=True)
    token = os.environ.get("REGISTRATION_TOKEN", config.REGISTRATION_TOKEN)
    
    # Eğer sertifikalar yoksa sunucudan talep et (auto-enroll)
    # Önce eski oturumdan kalmış olabilecek firewall izolasyon kurallarını temizle ki API'ye (Port 8000) erişebilsin
    if not os.path.exists(SPECIFIC_CERT) or not os.path.exists(SPECIFIC_KEY) or not os.path.exists(CA_CERT):
        try:
            import subprocess
            subprocess.run('netsh advfirewall firewall delete rule name="NocSentinelBlockOut"', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run('netsh advfirewall firewall delete rule name="NocSentinelBlockOutUDP"', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run('netsh advfirewall firewall delete rule name="NocSentinelBlockIn"', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    while not os.path.exists(SPECIFIC_CERT) or not os.path.exists(SPECIFIC_KEY) or not os.path.exists(CA_CERT):
        logger.info("[TLS] Sertifikalar eksik! Sunucudan otomatik kayit (Auto-Enroll) baslatiliyor...")
        success = certificate_manager.enroll_certificate(
            server_url=SERVER_HTTPS_URL,
            pc_name=PC_NAME,
            token=token,
            certs_dir=CERTS_DIR
        )
        if success:
            break
            
        logger.warning("[TLS] Sertifika otomatik kaydi yapilamadi. Sunucu kapali olabilir veya token gecersiz.")
        
        # Eğer varsayılan yedek sertifikalar varsa onlarla geçici olarak devam edebiliriz
        if os.path.exists(os.path.join(CERTS_DIR, "client.crt")) and os.path.exists(os.path.join(CERTS_DIR, "client.key")):
            logger.warning("[TLS] Varsayilan paylasimli istemci sertifikalari bulundu. Bunlarla devam ediliyor.")
            break
            
        logger.error("[TLS] Hicbir sertifika bulunamadi! Sunucu baglantisi bekleniyor (10 saniye sonra tekrar denenecek)...")
        time.sleep(10)

# Ajan sertifikalarını hazırla (Sunucu ayaktaysa otomatik kaydolur)
init_agent_certificates()

if os.path.exists(SPECIFIC_CERT) and os.path.exists(SPECIFIC_KEY):
    CLIENT_CERT = SPECIFIC_CERT
    CLIENT_KEY = SPECIFIC_KEY
    logger.info(f"[TLS] '{PC_NAME}' adina ozel X.509 sertifikasi yuklendi: {os.path.basename(CLIENT_CERT)}")
else:
    CLIENT_CERT = os.path.join(CERTS_DIR, "client.crt")
    CLIENT_KEY = os.path.join(CERTS_DIR, "client.key")
    logger.warning("[TLS] Ozel sertifika bulunamadi, paylasimli istemci sertifikasi yuklendi.")

outgoing_queue = queue.PriorityQueue()

# Thread-safe asenkron kuyruk sayaç kontrolörü
queue_counter = 0
queue_counter_lock = threading.Lock()

def get_next_queue_id():
    global queue_counter
    with queue_counter_lock:
        queue_counter += 1
        return queue_counter

# Ajan tarafı sade Token Bucket: göndermeden önce kendi içinde hız sınırını uygular
_sender_bucket = TokenBucket()

# Bağlantı Durum Takibi
is_connected = False
is_server_online = False
mqtt_client = None
_last_mqtt_ping = time.time()

# ======================= MQTT CALLBACKS =======================

def on_connect(client, userdata, flags, rc, properties=None):
    global is_connected, is_server_online, _last_mqtt_ping
    if rc == 0:
        is_connected = True
        is_server_online = True  # Varsayılan olarak sunucuyu online kabul et
        _last_mqtt_ping = time.time()  # Watchdog icin baslangic noktasi
        logger.info("[MQTT] Sunucuya basariyla baglanildi.")
        control_topic = f"network/control/{PC_NAME}"
        client.subscribe(control_topic, qos=1)
        logger.info(f"[MQTT] Kontrol kanalina abone olundu: {control_topic}")
        # Sunucu durum kanalına abone ol
        client.subscribe("network/server/status", qos=1)
        logger.info("[MQTT] Sunucu durum kanalina abone olundu.")
        
        # Sunucuya başlangıç el sıkışmasını gönder (şifreli ve sıkıştırılmış olarak)
        try:
            startup_payload = {
                "pc_name": PC_NAME,
                "pc_priority": PC_PRIORITY,
                "status": "started"
            }
            encrypted_payload = CryptoHelper.encrypt_and_compress(startup_payload)
            client.publish(f"network/client/startup/{PC_NAME}", encrypted_payload, qos=1)
            logger.info("[MQTT] Sunucuya baslangic el sikismasi (startup handshake) gonderildi.")
        except Exception as e:
            logger.error(f"[MQTT] Startup handshake gonderilirken hata: {e}")
    else:
        is_connected = False
        logger.error(f"[MQTT] Baglanti hatasi: Donus kodu: {rc}")

def on_disconnect(client, userdata, disconnect_flags, rc, properties=None):
    global is_connected, is_server_online
    is_connected = False
    is_server_online = False
    logger.warning(f"[MQTT] Sunucu baglantisi kesildi. Donus kodu: {rc}")

def on_message(client, userdata, msg):
    global is_server_online, _last_mqtt_ping
    _last_mqtt_ping = time.time()  # Sunucudan (herhangi bir topic'te) mesaj geldiğinde tazelenir
    if msg.topic == "network/server/status":
        try:
            status = msg.payload.decode('utf-8', errors='ignore')
            if status == "online":
                if not is_server_online:
                    is_server_online = True
                    logger.info("[SUNUCU] Alici sunucu aktif! Cevrimdisi loglarin gonderimi tetikleniyor...")
                    threading.Thread(target=send_offline_logs, args=(client,), daemon=True).start()
            else:
                is_server_online = False
                logger.warning("[SUNUCU] Alici sunucu cevrimdisi! Yeni loglar yerel veritabaninda saklanacak.")
        except Exception as e:
            logger.error(f"[SUNUCU] Durum mesaji cozumlenirken hata: {e}")
    else:
        on_control_message(client, userdata, msg)

# ======================= KOMUT İŞLEME =======================

# ---------------------------------------------------------------------------
# Ağ İzolasyon Durum Takibi (Gemini'nin bulduğu "Firewall Kural Şişmesi" fix'i)
# ---------------------------------------------------------------------------
# Sorun: ISOLATE/LOCKDOWN geldiğinde cihaz ZATEN izole olsa bile önceki kod
# yine de 6 subprocess.run (3 delete + 3 add, ~150-300ms/komut, ~1.5-2sn
# toplam) çalıştırıyordu — üstelik bu, MQTT'nin on_message callback'i
# içinde SENKRON çalıştığı için o süre boyunca MQTT network loop thread'i
# bloke oluyor, ardışık ISOLATE komutları (24h test gibi yoğun senaryolarda)
# heartbeat/keepalive'ı geciktirip cihazın sunucu tarafında "Offline"
# görünmesine yol açabiliyordu (sorun.txt'deki çökmelerin olası nedenlerinden
# biri de bu). Çözüm: sadece durum GEÇİŞİNDE (Normal<->İzole) netsh çalıştır.
_isolation_state_lock = threading.Lock()
_is_network_isolated = False  # Bu process'in bildiği son durum

def _firewall_rule_exists(rule_name: str) -> bool:
    """Verilen netsh kuralının şu anda OS üzerinde gerçekten var olup olmadığını kontrol eder."""
    try:
        result = subprocess.run(
            f'netsh advfirewall firewall show rule name="{rule_name}"',
            shell=True, capture_output=True, text=True, timeout=5
        )
        # Kural yoksa netsh "No rules match the specified criteria." döner.
        return "No rules match" not in (result.stdout or "") and result.returncode == 0
    except Exception as e:
        logger.error(f"[IZOLASYON] Firewall kural kontrolu basarisiz ({rule_name}): {e}")
        return False

def _sync_isolation_state_from_os():
    """Script başlangıcında (veya yeniden başlatıldığında) in-memory bayrağı
    GERÇEK OS durumuyla senkronlar. Bu olmadan: script yeniden başlatılırsa
    bayrak sıfırlanır ama kurallar OS'ta hâlâ duruyor olabilir — sonraki bir
    RECOVER, bayrak zaten False olduğu için atlanır ve cihaz SONSUZA KADAR
    izole kalır. Bu fonksiyon bu riski ortadan kaldırır."""
    global _is_network_isolated
    with _isolation_state_lock:
        _is_network_isolated = _firewall_rule_exists("NocSentinelBlockOut")
        logger.info(f"[IZOLASYON] Başlangıç OS durumu senkronlandı: izole={_is_network_isolated}")

def _apply_network_isolation():
    """ISOLATE/LOCKDOWN için firewall kurallarını uygular — SADECE cihaz
    şu anda izole DEĞİLSE. Zaten izoleyse hiçbir subprocess çalıştırmaz."""
    global _is_network_isolated
    with _isolation_state_lock:
        if _is_network_isolated:
            logger.info("[IZOLASYON] Cihaz zaten izole durumda, kurallar tekrar uygulanmadi (redundant apply atlandi).")
            return
        try:
            subprocess.run('netsh advfirewall firewall delete rule name="NocSentinelBlockOut"', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run('netsh advfirewall firewall delete rule name="NocSentinelBlockOutUDP"', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run('netsh advfirewall firewall delete rule name="NocSentinelBlockIn"', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # Hem MQTT (8883) hem de Sentinel Admin/API (8000) kontrol trafiği için açık bırakılır
            cmd_out = 'netsh advfirewall firewall add rule name="NocSentinelBlockOut" dir=out action=block protocol=TCP remoteport=1-7999,8001-8882,8884-65535'
            subprocess.run(cmd_out, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            cmd_out_udp = 'netsh advfirewall firewall add rule name="NocSentinelBlockOutUDP" dir=out action=block protocol=UDP'
            subprocess.run(cmd_out_udp, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            cmd_in = 'netsh advfirewall firewall add rule name="NocSentinelBlockIn" dir=in action=block'
            subprocess.run(cmd_in, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            _is_network_isolated = True
            logger.critical("[IZOLASYON] Guvenlik duvari izolasyon kurallari basariyla uygulandi.")
        except Exception as e:
            logger.error(f"[IZOLASYON] Ag izolasyonu guvenlik duvari kurallari eklenirken hata: {e}")

def _clear_network_isolation():
    """RECOVER için firewall kurallarını temizler — SADECE cihaz şu anda
    izoleyse. Değilse hiçbir subprocess çalıştırmaz."""
    global _is_network_isolated
    with _isolation_state_lock:
        if not _is_network_isolated:
            logger.info("[IZOLASYON] Cihaz zaten normal modda, RECOVER icin ekstra komut calistirilmadi.")
            return
        try:
            subprocess.run('netsh advfirewall firewall delete rule name="NocSentinelBlockOut"', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run('netsh advfirewall firewall delete rule name="NocSentinelBlockOutUDP"', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run('netsh advfirewall firewall delete rule name="NocSentinelBlockIn"', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            _is_network_isolated = False
            logger.info("[IZOLASYON] Ag erisimi basariyla geri yuklendi.")
        except Exception as e:
            logger.error(f"[IZOLASYON] Guvenlik duvari kurallari temizlenirken hata: {e}")

def on_control_message(client, userdata, msg):
    """Sunucudan gelen şifreli kontrol komutlarını yorumlar."""
    global original_fill_rate, original_capacity
    try:
        command = CryptoHelper.decrypt_and_decompress(msg.payload)
        action = command.get("action")
        logger.info(f"[KOMUT] Sunucudan komut alindi: {action}")
        
        if action == "BLOCK_APP":
            target_hash = command.get("app_hash")
            target_name = command.get("app_name")
            logger.warning(f"[BLOCK_APP] Surec durdurulacak: {target_name} | Hash: {target_hash}")
            
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    proc_name = proc.info['name']
                    exe_path = proc.info['exe']
                    killed = False
                    
                    if exe_path and target_hash and target_hash != "Unknown" and target_hash is not None:
                        from monitors import get_file_hash
                        proc_hash = get_file_hash(exe_path)
                        if proc_hash == target_hash:
                            logger.error(f"[BLOCK_APP] Surec sonlandirildi (Hash ile): {proc_name} (PID: {proc.info['pid']})")
                            proc.kill()
                            killed = True
                            
                    if not killed and proc_name and target_name and target_name != "Unknown":
                        if proc_name.lower() == target_name.lower():
                            logger.error(f"[BLOCK_APP] Surec sonlandirildi (Ad ile): {proc_name} (PID: {proc.info['pid']})")
                            proc.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                    
        elif action == "RESTRICT":
            logger.warning("[RESTRICT] Kisitlama emri alindi! Bant genisligi sinirlandiriliyor...")
            if original_fill_rate is None:
                original_fill_rate = _sender_bucket.fill_rate
                original_capacity = _sender_bucket.capacity
            
            # Hızı 512 byte/sn'ye düşür
            restricted_rate = 512.0
            _sender_bucket.update_params(fill_rate=restricted_rate)
            logger.info(f"[RESTRICT] Iletim hizi sinirlandirildi: {restricted_rate} byte/sn")
            
        elif action == "ISOLATE":
            logger.critical("[ISOLATE] Ag izolasyon emri alindi! Guvenlik duvari kurallari aktif ediliyor...")
            # netsh çağrıları MQTT thread'ini bloke etmesin diye arka plana alındı.
            # Sıralama, _isolation_state_lock ile korunuyor (aynı anda tek thread
            # netsh çalıştırabilir), sadece hangi thread'in önce başladığı garanti değil
            # — bu, seyrek/state-transition-only komutlar için kabul edilebilir.
            threading.Thread(target=_apply_network_isolation, daemon=True).start()
                
        elif action == "LOCKDOWN":
            logger.critical("[LOCKDOWN] Merkezi LOCKDOWN emri alindi! Masaustu kilitleniyor ve ag izole ediliyor...")
            try:
                # 1. Windows Oturum Ekranını Kilitle (ucuz işlem, her zaman çalıştırılır —
                #    kullanıcı ekranı manuel açmış olabilir, tekrar kilitlemek istenir)
                ctypes.windll.user32.LockWorkStation()
                logger.critical("[LOCKDOWN] Bilgisayar ekrani kilitlendi.")

                # 2. Ağ İzolasyonu — sadece durum geçişinde, ve MQTT thread'ini
                #    bloke etmemesi için arka planda çalıştırılır.
                threading.Thread(target=_apply_network_isolation, daemon=True).start()
            except Exception as e:
                logger.error(f"[LOCKDOWN] Karantina kurallari eklenirken hata: {e}")
                
        elif action == "RECOVER":
            logger.info("[RECOVER] Kurtarma emri alindi! Kisitlamalar kaldiriliyor ve ag erisimi geri yukleniyor...")
            
            # 1. Hız limitlerini geri al
            if original_fill_rate is not None:
                _sender_bucket.update_params(capacity=original_capacity, fill_rate=original_fill_rate)
                original_fill_rate = None
                original_capacity = None
                logger.info("[RECOVER] Bant genisligi hiz sinirlari eski haline getirildi.")
                
            # 2. Güvenlik duvarı kurallarını temizle — sadece izole durumdaysa,
            #    ve MQTT thread'ini bloke etmemesi için arka planda çalıştırılır.
            threading.Thread(target=_clear_network_isolation, daemon=True).start()
                
        elif action == "UPDATE_LIMITS":
            new_rate = command.get("fill_rate")
            new_capacity = command.get("capacity")
            if new_rate is not None or new_capacity is not None:
                # Kilitlenmeyi (deadlock) önlemek için asgari taban: en az 512B kapasite (tek paket boyutu) ve 64 B/s hız
                safe_rate = max(64.0, float(new_rate)) if new_rate is not None else None
                safe_capacity = max(512.0, float(new_capacity)) if new_capacity is not None else None
                _sender_bucket.update_params(capacity=safe_capacity, fill_rate=safe_rate)
                logger.info(f"[UPDATE_LIMITS] Hiz limitleri guncellendi | Kapasite: {safe_capacity} byte | Hiz: {safe_rate} byte/sn")
                
        elif action in ["SYNC_ALLOWED_HASHES", "SYNC_HASH_CACHE"]:
            hashes_list = command.get("hashes", [])
            update_hash_cache(hashes_list)
            
        elif action == "UPDATE_TELEMETRY_INTERVAL":
            global TELEMETRY_INTERVAL
            new_interval = command.get("interval", config.DEFAULT_TELEMETRY_INTERVAL)
            with _telemetry_interval_lock:
                TELEMETRY_INTERVAL = int(new_interval)
            logger.info(f"[TELEMETRI] Sunucu komutuyla telemetri araligi guncellendi: {TELEMETRY_INTERVAL}s")

        elif action == "UPDATE_PRIORITY":
            global PC_PRIORITY
            new_priority = command.get("priority")
            if new_priority is not None:
                with _pc_priority_lock:
                    PC_PRIORITY = int(new_priority)
                logger.info(f"[ONCELIK] Sunucu komutuyla cihaz onceligi guncellendi: {PC_PRIORITY}")

            
        elif action == "REQUEST_PROCESS_LIST":
            logger.info("[SURECLER] Sunucudan surec listesi istegi alindi.")

            # Exe hash önbelleği: aynı exe birden fazla kez okunmaz (svchost.exe gibi)
            _exe_hash_cache = {}

            def _hash_exe(exe_path):
                """Verilen exe yolunun SHA-256 hash'ini hesaplar. Sonuç önbelleklenir.
                100MB üstü, erişilemeyen veya bulunamayan dosyalar için None döner."""
                if exe_path in _exe_hash_cache:
                    return _exe_hash_cache[exe_path]
                try:
                    if not os.path.isfile(exe_path):
                        _exe_hash_cache[exe_path] = None
                        return None
                    if os.path.getsize(exe_path) > 100 * 1024 * 1024:  # 100 MB sınırı
                        _exe_hash_cache[exe_path] = None
                        return None
                    h = hashlib.sha256()
                    with open(exe_path, "rb") as f:
                        for chunk in iter(lambda: f.read(65536), b""):
                            h.update(chunk)
                    result = h.hexdigest()
                    _exe_hash_cache[exe_path] = result
                    return result
                except (PermissionError, OSError):
                    _exe_hash_cache[exe_path] = None
                    return None

            process_list = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
                try:
                    # Temel bilgiler
                    entry = {
                        "pid":        proc.info['pid'],
                        "name":       proc.info['name'],
                        "cpu":        proc.info['cpu_percent'] if proc.info['cpu_percent'] else 0.0,
                        "ram_mb":     round(proc.info['memory_info'].rss / (1024 * 1024), 1) if proc.info['memory_info'] else 0.0,
                        "exe_path":   None,
                        "hash_sha256": None,
                    }
                    # Exe yolu ve hash (AccessDenied → None olarak bırakılır)
                    try:
                        exe = psutil.Process(proc.info['pid']).exe()
                        if exe:
                            entry["exe_path"]   = exe
                            entry["hash_sha256"] = _hash_exe(exe)
                    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                        pass

                    process_list.append(entry)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                    
            response = {
                "pc_name": PC_NAME,
                "type": "PROCESS_LIST",
                "processes": process_list
            }
            enc_response = CryptoHelper.encrypt_and_compress(response)
            client.publish(f"network/client/processes/{PC_NAME}", enc_response, qos=1)
            logger.info(f"[SURECLER] {len(process_list)} surec bilgisi sunucuya gonderildi.")
            
        elif action == "KILL_PROCESS":
            pid_to_kill = command.get("pid")
            process_name = command.get("process_name", "")
            logger.warning(f"[KILL] Sunucudan PID {pid_to_kill} ({process_name}) icin sonlandirma emri alindi.")
            try:
                if pid_to_kill:
                    proc = psutil.Process(pid_to_kill)
                    proc.kill()
                    logger.error(f"[KILL] Surec basariyla sonlandirildi: PID {pid_to_kill} ({process_name})")
            except psutil.NoSuchProcess:
                logger.warning(f"[KILL] Belirtilen PID bulunamadi: {pid_to_kill}")
            except psutil.AccessDenied:
                logger.error(f"[KILL] Sureci sonlandirmak icin yetki yetersiz: PID {pid_to_kill}")
            except Exception as e:
                logger.error(f"[KILL] Surec sonlandirilirken hata: {e}")

    except Exception as e:
        logger.error(f"[KOMUT] Kontrol mesaji islenirken hata: {e}")

# ======================= LOG GÖNDERİM / KUYRUK YÖNETİMİ =======================

def queue_log(log_level: str, log_priority: float, message: str, app_name: str = "Unknown", app_hash: str = "Unknown"):
    """Log paketini hazirlar ve oncelikli gonderme kuyruguna ekler.

    ÖNEMLİ (gecikme/kısıtlama ölçümü için değişti): Paket artık BURADA
    şifrelenmiyor. Neden: gerçek "kısıtlama gecikmesi" (bant genişliği
    darboğazı yüzünden mesajın kuyrukta bekleme süresi), tam olarak
    batch_sender()'daki token-bucket bekleyişi sırasında oluşuyor. Paket
    burada şifrelenip kilitlenirse, o bekleme süresini paketin içine daha
    sonra ekleyemeyiz. Bu yüzden şifreleme, gerçek gönderim anına
    (client_send_ts eklendikten hemen sonra) ertelendi. Kuyruk artık
    şifreli byte yerine ham dict + boyut tahmini taşıyor.

    log_priority  : Sunucuya gonderilen 0-10 arasi gercek/normalize skor.
    queue_priority: SADECE kuyruk sirasi icin, log_priority ile ayni (zaten 0-10).
    """
    queue_priority = float(log_priority)

    log_data = {
        "pc_name": PC_NAME,
        "pc_priority": get_pc_priority(),  # Thread-safe okuma (lock ile)
        "log_level": log_level,
        "log_priority": log_priority,   # Sunucuya giden gercek skor
        "message": message,
        "app_name": app_name,
        "app_hash": app_hash,
        "timestamp": time.time(),        # Geriye donuk uyumluluk icin korunuyor
        "client_create_ts": time.time(), # YENİ: olayın algılanıp kuyruğa girdiği an
    }
    try:
        # Sadece token-bucket boyut tahmini için geçici bir şifreleme yapılır.
        # Gerçek gönderilecek (nihai) paket, batch_sender() içinde
        # client_send_ts eklendikten SONRA yeniden şifrelenir.
        _size_estimate_payload = CryptoHelper.encrypt_and_compress(log_data)
        estimated_size = len(_size_estimate_payload)
        # PriorityQueue: (-queue_priority, id, log_priority, topic, log_data, estimated_size)
        outgoing_queue.put((-queue_priority, get_next_queue_id(), log_priority, f"network/logs/{PC_NAME}", log_data, estimated_size))
        logger.debug(
            f"[KUYRUK] Eklendi | Seviye={log_level} | SunucuSkoru={log_priority} | "
            f"KuyrukOncelik={queue_priority}/10"
        )
    except Exception as e:
        logger.error(f"[KUYRUK] Log hazirlanirken veya kuyruga eklenirken hata: {e}")

def batch_sender(client):
    """Kuyruktan logları çeker, TokenBucket hız sınırına uyarak sunucuya gönderir/önbelleğe alır.

    client_send_ts, token-bucket bekleyişi TAMAMLANDIKTAN hemen sonra,
    fiili client.publish() çağrısından hemen önce damgalanır — yani
    bant genişliği kısıtlamasının yarattığı gerçek gecikmeyi (client_send_ts
    - client_create_ts) doğru yansıtır.
    """
    logger.info("[SENDER] Log gonderim dongusu aktif.")
    while True:
        try:
            _, _, priority, topic, log_data, estimated_size = outgoing_queue.get()

            # Kendi hız sınırımıza uymak için jeton tüketmesini bekle
            # (boyut tahmini kullanılıyor; nihai şifreli boyut birkaç byte
            # farklı olabilir ama token-bucket muhasebesi için ihmal edilebilir)
            while not _sender_bucket.consume(estimated_size):
                time.sleep(0.05)

            # GERÇEK GÖNDERİM ANI — kısıtlama/kuyruklama gecikmesi burada damgalanır
            log_data["client_send_ts"] = time.time()

            try:
                encrypted_payload = CryptoHelper.encrypt_and_compress(log_data)
            except Exception as e:
                logger.error(f"[SENDER] Nihai paket sifrelenirken hata: {e}")
                outgoing_queue.task_done()
                continue

            if is_connected and is_server_online:
                client.publish(topic, encrypted_payload, qos=1)
            else:
                save_log_offline(topic, encrypted_payload, log_priority=priority)

            outgoing_queue.task_done()
        except Exception as e:
            logger.error(f"[SENDER] Gonderim dongusu hatasi: {e}")
            time.sleep(1)

def publish_telemetry(telemetry_data):
    """Telemetri verisini şifreleyerek MQTT veya yerel önbellek üzerinden gönderir."""
    try:
        encrypted_payload = CryptoHelper.encrypt_and_compress(telemetry_data)
        telemetry_topic = f"network/telemetry/{PC_NAME}"
        if is_connected and is_server_online:
            mqtt_client.publish(telemetry_topic, encrypted_payload, qos=0)
        else:
            save_log_offline(telemetry_topic, encrypted_payload, log_priority=5)
    except Exception as e:
        logger.error(f"[TELEMETRI] Telemetri gonderilirken hata: {e}")

def certificate_renew_monitor():
    """Sertifika geçerlilik süresini izler ve son 30 gün kala yeniler."""
    if not CERT_MANAGER_AVAILABLE:
        return
        
    logger.info("[TLS] Sertifika yenileme izleyicisi aktif.")
    SERVER_HTTPS_URL = get_admin_api_url("yenileme", exit_on_error=False)
    
    while True:
        # Her 1 saatte bir kontrol et (days_threshold=30)
        time.sleep(3600)
        try:
            if certificate_manager.check_cert_expiry(CERTS_DIR, PC_NAME, days_threshold=30):
                logger.info("[TLS] Sertifikanin suresi dolmak uzere! Yenileme baslatiliyor...")
                success = certificate_manager.renew_certificate(SERVER_HTTPS_URL, PC_NAME, CERTS_DIR)
                if success:
                    logger.info("[TLS] Sertifika basariyla yenilendi, MQTT baglantisi yenilenecek...")
                    mqtt_client.disconnect()
        except Exception as e:
            logger.error(f"[TLS] Sertifika yenileme izleyici hatasi: {e}")

# ======================= BAŞLATMA / ORKESTRASYON =======================

def main():
    global mqtt_client, MQTT_PORT
    init_offline_db()

    # ÖNEMLİ: script yeniden başlatıldığında (24h test sırasında client
    # restart edilmesi gibi) in-memory izolasyon bayrağının gerçek OS
    # durumuyla senkron başlamasını sağlar — aksi halde eski izolasyon
    # kuralları OS'ta kalıp bir daha hiç RECOVER ile temizlenemeyebilir.
    _sync_isolation_state_from_os()

    mqtt_client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id=MQTT_CLIENT_ID,
        clean_session=True
    )
    mqtt_client.on_connect = on_connect
    mqtt_client.on_disconnect = on_disconnect
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
                logger.info(f"[TLS] Ajan SSL/TLS aktif edildi. Guvenli port {MQTT_PORT}'e gecildi.")
            except Exception as tls_err:
                logger.critical(f"[TLS] Ajan TLS ayarlanirken kritik hata: {tls_err}")
                sys.exit(1)
        else:
            logger.critical("[TLS] Kritik Hata: SSL/TLS sertifikalari bulunamadi! Sistem durduruluyor.")
            sys.exit(1)
    else:
        MQTT_PORT = config.MQTT_PORT
        logger.info(f"[MQTT] SSL/TLS devre disi (Port: {MQTT_PORT}). Standart MQTT baglantisi kullaniliyor.")

    mqtt_client.reconnect_delay_set(min_delay=1, max_delay=30)
    
    # Alt izleme ajanlarını başlat (Supervisor ile — çökme durumunda otomatik yeniden başlar)
    supervise_thread(system_monitor, args=(queue_log, PC_NAME), name="SystemMonitor")
    supervise_thread(event_log_monitor, args=(queue_log,), name="EventLogMonitor")
    supervise_thread(batch_sender, args=(mqtt_client,), name="BatchSender")
    supervise_thread(telemetry_sender, args=(publish_telemetry, queue_log, PC_NAME, get_telemetry_interval), name="TelemetrySender")
    supervise_thread(certificate_renew_monitor, name="CertRenewMonitor")
    
    logger.info(f"[AJAN] {PC_NAME} izleme ajanlari ve veri kuyruklari baslatildi (Supervisor aktif).")

    try:
        mqtt_client.connect_async(MQTT_BROKER, MQTT_PORT, keepalive=60)
        mqtt_client.loop_start()
    except Exception as conn_err:
        logger.error(f"[MQTT] Asenkron baglanti baslatılamadi: {conn_err}")

    logger.info(f"[AJAN] {PC_NAME} Uc Nokta Guvenlik Ajani basariyla baslatildi.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("[AJAN] Ajan kapatiliyor...")
        mqtt_client.loop_stop()

if __name__ == "__main__":
    main()