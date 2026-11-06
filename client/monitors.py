import os
import time
import hashlib
import logging
import psutil
import threading
import sys
import json
from collections import OrderedDict
from utils.path_helper import get_base_dir
try:
    import win32evtlog
except ImportError:
    win32evtlog = None

logger = logging.getLogger("AgentMonitors")

# Hash önbelleği: En fazla 512 kaydı tut (bellek sızıntısını önler)
_HASH_CACHE_MAX = 512
FILE_HASH_CACHE = OrderedDict()
_hash_cache_lock = threading.Lock()
SEEN_PIDS = set()
_seen_pids_lock = threading.Lock()

# Sunucu kontrollü beyaz liste (Allowed Hashes) yönetimi -> Anlık Darboğaz Önleyici Önbellek
base_dir = get_base_dir()
common_path = os.path.join(os.path.dirname(base_dir), "common")
if os.path.exists(common_path):
    sys.path.insert(0, common_path)
SCANNED_HASHES_FILE = os.path.join(base_dir, "scanned_hashes_cache.json")
SCANNED_HASH_CACHE = set()
_scanned_hash_lock = threading.Lock()

def load_hash_cache():
    global SCANNED_HASH_CACHE
    with _scanned_hash_lock:
        if os.path.exists(SCANNED_HASHES_FILE):
            try:
                with open(SCANNED_HASHES_FILE, "r") as f:
                    data = json.load(f)
                    SCANNED_HASH_CACHE = set(data.get("hashes", []))
                    logger.info(f"[ONBELLEK] Yerel hash onbelleginden {len(SCANNED_HASH_CACHE)} adet hash yuklendi.")
            except Exception as e:
                logger.error(f"[ONBELLEK] Yerel hash onbellegi yuklenirken hata: {e}")
        else:
            SCANNED_HASH_CACHE = set()
            logger.info("[ONBELLEK] Yerel hash onbellegi dosyasi bulunamadi, bos olarak baslatildi.")

def update_hash_cache(hashes_list):
    global SCANNED_HASH_CACHE
    with _scanned_hash_lock:
        SCANNED_HASH_CACHE = set(hashes_list)
        try:
            with open(SCANNED_HASHES_FILE, "w") as f:
                json.dump({"hashes": list(SCANNED_HASH_CACHE)}, f, indent=4)
            logger.info(f"[ONBELLEK] Yerel hash onbellegi basariyla senkronize edildi: {len(SCANNED_HASH_CACHE)} adet hash kaydedildi.")
        except Exception as e:
            logger.error(f"[ONBELLEK] Yerel hash onbellegi kaydedilirken hata: {e}")


def get_file_hash(filepath: str) -> str:
    """Dosyanın SHA-256 hash değerini hesaplar ve önbelleğe yazar. Double-check pattern ile TOCTOU'dan korunur."""
    # 1. Hızlı cache kontrolü (lock içinde)
    with _hash_cache_lock:
        if filepath in FILE_HASH_CACHE:
            FILE_HASH_CACHE.move_to_end(filepath)
            return FILE_HASH_CACHE[filepath]

    # 2. Lock DİŞİNDA hash hesapla (dosya I/O yavaş olabilir, lock tutulmamalı)
    hasher = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for buf in iter(lambda: f.read(65536), b''):
                hasher.update(buf)
        file_hash = hasher.hexdigest()
    except Exception:
        return None

    # 3. Tekrar lock alarak yaz (başka thread aynı sırada yazmış olabilir)
    with _hash_cache_lock:
        if filepath not in FILE_HASH_CACHE:
            FILE_HASH_CACHE[filepath] = file_hash
            if len(FILE_HASH_CACHE) > _HASH_CACHE_MAX:
                FILE_HASH_CACHE.popitem(last=False)
        return FILE_HASH_CACHE[filepath]

def system_monitor(queue_log_fn, pc_name: str):
    """Çalışan süreçleri tarar ve yeni açılan süreçlerin hash'ini sunucuya yollar."""
    logger.info("[SUREC GOZLEMCISI] Baslatiliyor, hash onbellek senkronizasyonu bekleniyor...")
    time.sleep(5)
    load_hash_cache()
    logger.info("[SUREC GOZLEMCISI] Aktif. Baslangic envanter taramasi yapiliyor...")
    
    # EDR Envanter Yaklaşımı: Başlangıçta çalışan süreçleri sadece SEEN_PIDS havuzuna ekle (Sunucuya alarm logu atma)
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            pid = proc.info['pid']
            exe_path = proc.info['exe']
            if exe_path:
                with _seen_pids_lock:
                    SEEN_PIDS.add(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    logger.info(f"[SUREC GOZLEMCISI] Baslangic taramasi tamamlandi. {len(SEEN_PIDS)} adet surec envantere kaydedildi.")

    while True:
        try:
            # Aktif süreçlerin PID'lerini topla ve yeni açılanları yakala
            active_pids = set()
            new_processes = []
            
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    pid = proc.info['pid']
                    active_pids.add(pid)
                    
                    with _seen_pids_lock:
                        already_seen = pid in SEEN_PIDS
                    
                    if not already_seen:
                        new_processes.append(proc)
                        # PID'yi hemen kaydet; hash hesaplama lock dışında yapılıyor
                        with _seen_pids_lock:
                            SEEN_PIDS.add(pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # Artık aktif olmayan PID'leri hafızadan sil (Güvenlik Açığı Önleme - PID Recycling)
            with _seen_pids_lock:
                SEEN_PIDS.intersection_update(active_pids)

            # Yeni süreçlerin hash'ini hesapla ve yolla
            for proc in new_processes:
                exe_path = proc.info.get('exe')
                if exe_path:
                    app_hash = get_file_hash(exe_path)
                    if app_hash:
                        # Kriptografik önbellek doğrulaması
                        if app_hash in SCANNED_HASH_CACHE:
                            continue
                            
                        logger.info(f"[YENI SUREC] {proc.info['name']} | PID: {proc.info['pid']} | Hash: {app_hash[:16]}...")
                        queue_log_fn(
                            log_level="INFO",
                            log_priority=4,
                            message=f"Yeni uygulama başlatıldı: {proc.info['name']}",
                            app_name=proc.info['name'],
                            app_hash=app_hash
                        )
            time.sleep(10)
        except Exception as e:
            logger.error(f"[SUREC GOZLEMCISI] Dongü hatasi: {e}")
            time.sleep(10)

import queue
import app_config as config

# YEREL BAŞARISIZ GİRİŞ TAKİBİ
FAILED_LOGON_TIMESTAMPS = []
_failed_logon_lock = threading.Lock()

def fallback_heuristic_eval(event_id: int, message: str, failed_count: int = 0) -> dict:
    """İnternet kesik veya API kapalıyken çalışan yerel kurallar matrisi."""
    if event_id in [1100, 1102]:
        return {
            "is_suspicious": True,
            "risk_score": 95,
            "level": "EMERGENCY",
            "reason": f"Olay günlüğü hizmeti silindi veya durduruldu! EventID={event_id} (Yerel Fallback Koruması)."
        }
    elif event_id == 4720:
        return {
            "is_suspicious": True,
            "risk_score": 85,
            "level": "CRITICAL",
            "reason": "Yeni yerel kullanıcı hesabı oluşturuldu (Yerel Fallback Koruması)."
        }
    elif event_id == 4732:
        return {
            "is_suspicious": True,
            "risk_score": 90,
            "level": "CRITICAL",
            "reason": "Yönetici (Administrators) grubuna yeni üye eklendi (Yerel Fallback Koruması)."
        }
    elif event_id in [4739, 4740]:
        return {
            "is_suspicious": True,
            "risk_score": 80,
            "level": "CRITICAL",
            "reason": f"Etki alanı politikası değiştirildi veya kullanıcı hesabı kilitlendi (EventID={event_id})."
        }
    elif event_id == 4726:
        return {
            "is_suspicious": True,
            "risk_score": 70,
            "level": "WARNING",
            "reason": "Yerel kullanıcı hesabı silindi (Yerel Fallback Koruması)."
        }
    elif event_id in [4697, 7045]:
        return {
            "is_suspicious": True,
            "risk_score": 75,
            "level": "WARNING",
            "reason": f"Sisteme yeni servis/arka plan hizmeti yüklendi (Yerel Fallback Koruması)."
        }
    elif event_id in [4698, 4699, 4702]:
        return {
            "is_suspicious": True,
            "risk_score": 70,
            "level": "WARNING",
            "reason": f"Zamanlanmış görev oluşturuldu/değiştirildi/silindi (EventID={event_id})."
        }
    elif event_id in [4728, 4729, 4733, 4735, 4737, 4738, 4704, 4719, 4756, 4757]:
        return {
            "is_suspicious": True,
            "risk_score": 65,
            "level": "WARNING",
            "reason": f"Kritik grup, kullanıcı niteliği veya denetim politikası değiştirildi (EventID={event_id})."
        }
    elif event_id in [4648, 4672, 4673, 4674, 4722, 4725]:
        return {
            "is_suspicious": True,
            "risk_score": 60,
            "level": "WARNING",
            "reason": f"Ayrıcalıklı oturum/kimlik kullanımı veya hesap durumu değişti (EventID={event_id})."
        }
    elif event_id == 4625:
        # Ardışık başarısızlık sayısına göre yerel kural motoru risk skorunu artırır
        if failed_count >= 5:
            return {
                "is_suspicious": True,
                "risk_score": 85,
                "level": "CRITICAL",
                "reason": f"Sık ardışık başarısız oturum açma denemesi ({failed_count} kez, Brute Force şüphesi, Yerel Fallback)."
            }
        elif failed_count >= 3:
            return {
                "is_suspicious": True,
                "risk_score": 65,
                "level": "WARNING",
                "reason": f"Müteakip başarısız oturum açma denemesi ({failed_count} kez, Yerel Fallback)."
            }
        else:
            return {
                "is_suspicious": False,
                "risk_score": 10,
                "level": "INFO",
                "reason": "Tekil veya 3'ün altındaki başarısız oturum açma denemesi yerel olarak elendi (Yerel Fallback)."
            }
    return {
        "is_suspicious": False,
        "risk_score": 0,
        "level": "INFO",
        "reason": "Şüpheli olmayan yerel olay."
    }


def process_log_event(event, queue_log_fn):
    """Windows log olayını kuyruğa asenkron analiz edilmek üzere ekler."""
    event_id = event.EventID & 0xFFFF
    monitored_events = [
        1100, 1102, 4624, 4625, 4634, 4648, 4672, 4673, 4674, 
        4697, 4698, 4699, 4702, 4704, 4719, 4720, 4722, 4725, 
        4726, 4728, 4729, 4732, 4733, 4735, 4737, 4738, 4739, 
        4740, 4756, 4757, 7045
    ]
    if event_id in monitored_events:
        inserts = []
        desc = ""
        failed_count = 0
        try:
            if event.StringInserts:
                inserts = [str(x) for x in event.StringInserts]
                desc = " | ".join(inserts)
        except Exception:
            pass

        # Yapısal Parsing (SubjectUserName / TargetUserName / TargetGroupName)
        subject_user = inserts[1] if len(inserts) > 1 and inserts[1] and inserts[1] != "-" else (inserts[0] if len(inserts) > 0 else "Bilinmeyen Yönetici")
        target_user  = inserts[0] if len(inserts) > 0 else "Bilinmeyen Kullanıcı"
        target_group = inserts[2] if len(inserts) > 2 else "Güvenlik Grubu"

        if event_id == 4625:
            now = time.time()
            with _failed_logon_lock:
                FAILED_LOGON_TIMESTAMPS.append(now)
                cutoff = now - 60
                while FAILED_LOGON_TIMESTAMPS and FAILED_LOGON_TIMESTAMPS[0] < cutoff:
                    FAILED_LOGON_TIMESTAMPS.pop(0)
                failed_count = len(FAILED_LOGON_TIMESTAMPS)
            desc = f"Başarısız Oturum Açma Denemesi! Kullanıcı: '{target_user}' | Son 1dk Deneme: {failed_count}"
        elif event_id == 4624:
            desc = f"Başarılı Oturum Açıldı! Kullanıcı: '{target_user}'"
        elif event_id == 4634:
            desc = f"Oturum Kapatıldı (Logoff)! Kullanıcı: '{target_user}'"
        elif event_id == 4648:
            desc = f"Farklı Kimlik Bilgileriyle Oturum Açıldı (Explicit Credentials)! Kullanıcı: '{subject_user}' -> '{target_user}'"
        elif event_id == 1102:
            desc = "Security Denetim Günlüğü Silindi!"
        elif event_id == 1100:
            desc = "Olay Günlüğü Hizmeti Durduruldu!"
        elif event_id == 4672:
            desc = f"Yönetici Ayrıcalıklarıyla Oturum Açıldı (Admin Special Logon)! Kullanıcı: '{target_user}'"
        elif event_id in [4673, 4674]:
            desc = f"Ayrıcalıklı Hizmet/Nesne Çağrısı Yapıldı! Kullanıcı: '{subject_user}'"
        elif event_id == 4720:
            desc = f"Yeni Kullanıcı Hesabı Oluşturuldu! Oluşturan: '{subject_user}' | Yeni Kullanıcı: '{target_user}'"
        elif event_id == 4722:
            desc = f"Kullanıcı Hesabı Aktifleştirildi! İşlemi Yapan: '{subject_user}' | Kullanıcı: '{target_user}'"
        elif event_id == 4725:
            desc = f"Kullanıcı Hesabı Devre Dışı Bırakıldı! İşlemi Yapan: '{subject_user}' | Kullanıcı: '{target_user}'"
        elif event_id == 4726:
            desc = f"Kullanıcı Hesabı Silindi! Silen: '{subject_user}' | Silinen Kullanıcı: '{target_user}'"
        elif event_id == 4740:
            desc = f"Kullanıcı Hesabı Kilitlendi (Locked Out)! Kullanıcı: '{target_user}'"
        elif event_id == 4732:
            desc = f"Administrators (Yönetici) Grubuna Üye EKLENDİ! Ekleyen: '{subject_user}' | Eklenen: '{target_user}' | Grup: '{target_group}'"
        elif event_id == 4733:
            desc = f"Administrators (Yönetici) Grubundan Üye ÇIKARILDI! Çıkaran: '{subject_user}' | Çıkarılan: '{target_user}' | Grup: '{target_group}'"
        elif event_id == 4728:
            desc = f"Güvenlik Grubuna Yeni Üye EKLENDİ! Ekleyen: '{subject_user}' | Eklenen: '{target_user}' | Grup: '{target_group}'"
        elif event_id == 4729:
            desc = f"Güvenlik Grubundan Üye ÇIKARILDI! Çıkaran: '{subject_user}' | Çıkarılan: '{target_user}' | Grup: '{target_group}'"
        elif event_id in [4735, 4737]:
            desc = f"Güvenlik Grubu Özellikleri Değiştirildi! Değiştiren: '{subject_user}' | Grup: '{target_user}'"
        elif event_id == 4738:
            desc = f"Kullanıcı Hesabı Özellikleri Değiştirildi! Değiştiren: '{subject_user}' | Kullanıcı: '{target_user}'"
        elif event_id in [4756, 4757]:
            action_str = "EKLENDİ" if event_id == 4756 else "ÇIKARILDI"
            desc = f"Evrensel Gruba Üye {action_str}! İşlemi Yapan: '{subject_user}' | Üye: '{target_user}'"
        elif event_id in [4698, 4699, 4702]:
            desc = f"Zamanlanmış Görev (Scheduled Task) Oluşturuldu/Değiştirildi! Yapan: '{subject_user}'"
        elif event_id in [4704, 4719, 4739]:
            desc = f"Güvenlik/Denetim Politikası Değiştirildi! Değiştiren: '{subject_user}'"
        elif event_id in [4697, 7045]:
            desc = f"Sisteme Yeni Servis Kuruldu! Details: {desc}"
            
        # Kural motorunu (fallback_heuristic_eval) senkron olarak cagir.
        eval_res = fallback_heuristic_eval(event_id, desc, failed_count)
        
        # Sadece supheli olaylari sunucuya rapor et
        if eval_res["is_suspicious"]:
            raw_score = eval_res["risk_score"]
            log_prio = round(raw_score / 10, 1)
            
            logger.warning(
                f"[SUPHELIOLAY] EventID={event_id} | Seviye={eval_res['level']} | "
                f"HamRisk={raw_score}/100 | NormalizeOncelik={log_prio}/10 | "
                f"Neden: {eval_res['reason']}"
            )
            
            queue_log_fn(
                log_level=eval_res["level"],
                log_priority=log_prio,
                message=f"Windows Event ID: {event_id} | {eval_res['reason']}",
                app_name="lsass.exe",
                app_hash="Unknown"
            )
        else:
            logger.debug(f"[FILTRE] Zararsiz olay elendi: EventID={event_id}")

def event_log_monitor(queue_log_fn):
    """Windows Security loglarını izler ve kritik güvenlik olaylarını raporlar."""
    if win32evtlog is None:
        logger.warning("[EVENT_LOG] pywin32 kutuphanesi ve Windows platformu gerekli. Event Log Gozlemcisi baslatilamadi.")
        return

    
    logger.info("[EVENT_LOG] Windows Security Event Log Gozlemcisi aktif.")
    server = "localhost"
    logtype = "Security"
    
    try:
        hand = win32evtlog.OpenEventLog(server, logtype)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        last_record_number = events[0].RecordNumber if events else 0
        win32evtlog.CloseEventLog(hand)
        logger.info(f"[EVENT_LOG] Baslangic RecordNumber belirlendi: {last_record_number}")
    except Exception as e:
        logger.error(f"[EVENT_LOG] Baslangic Event Log okuma hatasi: {e}")
        last_record_number = 0
            
    while True:
        time.sleep(10)
        try:
            hand = win32evtlog.OpenEventLog(server, logtype)
            try:
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                
                if events:
                    current_max = max(ev.RecordNumber for ev in events)
                    if current_max < last_record_number - 100:
                        logger.warning("[EVENT_LOG] Windows Security Event Log temizlenmis! RecordNumber sifirlaniyor.")
                        last_record_number = 0
                    
                    new_events = [ev for ev in events if ev.RecordNumber > last_record_number]
                    if new_events:
                        last_record_number = max(ev.RecordNumber for ev in new_events)
                        for event in reversed(new_events):
                            process_log_event(event, queue_log_fn)
            finally:
                win32evtlog.CloseEventLog(hand)
        except Exception as err:
            logger.debug(f"Event Log okuma hatası (normal olabilir): {err}")

def telemetry_sender(publish_telemetry_fn, queue_log_fn, pc_name: str, get_interval_fn=None):
    """30 saniyede bir CPU/RAM ve sıcaklık verisini şifreleyerek sunucuya iletir. Eşik değerler aşılırsa alarm üretir."""
    logger.info("[TELEMETRI] Donanim Telemetri Ajani aktif.")
    while True:
        try:
            cpu = psutil.cpu_percent(interval=None)
            ram = psutil.virtual_memory().percent
            
            temp = 0
            if hasattr(psutil, "sensors_temperatures"):
                temps = psutil.sensors_temperatures()
                if temps:
                    first_sensor = list(temps.values())[0]
                    if first_sensor:
                        temp = first_sensor[0].current

            telemetry_data = {
                "pc_name": pc_name,
                "cpu_percent": cpu,
                "ram_percent": ram,
                "cpu_temp": temp,
                "timestamp": time.time()
            }
            
            publish_telemetry_fn(telemetry_data)
            logger.info(f"[TELEMETRI] Veriler gonderildi | CPU: %{cpu} | RAM: %{ram} | Temp: {temp}C")
            
            # Donanım Eşik Değer Kontrolleri (Kritik kaynak uyarısı)
            warnings = []
            if cpu > 90.0:
                warnings.append(f"Yuksek CPU Kullanimi: %{cpu}")
            if ram > 90.0:
                warnings.append(f"Yuksek RAM Kullanimi: %{ram}")
            if temp > 80.0:
                warnings.append(f"Yuksek Sicaklik: {temp}C")
                
            for warn in warnings:
                queue_log_fn(
                    log_level="WARNING",
                    log_priority=6.0,  # 0-10 normalize ölçekte
                    message=f"[KAYNAK_LIMITI] {warn}",
                    app_name="System",
                    app_hash="Unknown"
                )
            
            interval = get_interval_fn() if get_interval_fn else 30
            time.sleep(interval)
        except Exception as e:
            logger.error(f"[TELEMETRI] Ajan hatasi: {e}")
            time.sleep(10)
