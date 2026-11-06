import os
import time
import sqlite3
import logging
import threading
import json
from utils.path_helper import get_base_dir, get_data_dir

base_dir = get_base_dir()
data_dir = get_data_dir()

logger = logging.getLogger("OfflineDB")

# Çevrimdışı logların saklanacağı veritabanı yolu
OFFLINE_DB_PATH = os.path.join(data_dir, "agent_offline.db")

# SQLite yazma kilidi
_offline_db_lock = threading.Lock()

def init_offline_db():
    """Çevrimdışı log veritabanını ilklendirir ve tabloları oluşturur."""
    global OFFLINE_DB_PATH
    os.makedirs(data_dir, exist_ok=True)
    conn = sqlite3.connect(OFFLINE_DB_PATH)

    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS offline_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            topic TEXT,
            payload BLOB,
            log_priority INTEGER DEFAULT 5,
            timestamp REAL
        )
    """)
    try:
        cursor.execute("ALTER TABLE offline_logs ADD COLUMN log_priority INTEGER DEFAULT 5")
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()

def save_log_offline(topic: str, payload: bytes, log_priority: int = 5):
    """Ağ koptuğunda logları yerel SQLite veritabanına kaydeder."""
    with _offline_db_lock:
        try:
            conn = sqlite3.connect(OFFLINE_DB_PATH, check_same_thread=False)
            cursor = conn.cursor()
            
            # --- RİNG BUFFER / BOYUT KISITLAMASI ---
            MAX_OFFLINE_LOGS = 10000
            cursor.execute("SELECT COUNT(*) FROM offline_logs")
            count = cursor.fetchone()[0]
            
            if count >= MAX_OFFLINE_LOGS:
                excess = count - MAX_OFFLINE_LOGS + 1
                cursor.execute(
                    "DELETE FROM offline_logs WHERE id IN ("
                    "SELECT id FROM offline_logs "
                    "ORDER BY log_priority ASC, timestamp ASC LIMIT ?"
                    ")",
                    (excess,)
                )
            
            cursor.execute(
                "INSERT INTO offline_logs (topic, payload, log_priority, timestamp) VALUES (?, ?, ?, ?)",
                (topic, payload, log_priority, time.time())
            )
            conn.commit()
            conn.close()
            logger.warning(f"[OFFLINE] Sunucu ulasilamiyor. Log SQLite'a kaydedildi. | Topic: {topic.split('/')[-1]} | Oncelik: {log_priority}")
        except Exception as e:
            logger.error(f"[OFFLINE] Yerel veritabanina yazilirken hata: {e}")

def send_offline_logs(client):
    """Bağlantı geri geldiğinde yerelde biriken logları sırayla gönderir.
    
    Deadlock önleme: Lock yalnızca DB okuma ve silme aşamasında tutulur.
    Ağ gönderimi (client.publish) lock dışında gerçekleşir.
    """
    # --- AŞAMA 1: Kilitli bölgede yalnızca okuma yap ---
    with _offline_db_lock:
        try:
            conn = sqlite3.connect(OFFLINE_DB_PATH, check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute("SELECT id, topic, payload FROM offline_logs ORDER BY timestamp ASC")
            rows = cursor.fetchall()
            conn.close()
        except Exception as e:
            logger.error(f"[OFFLINE] Cevrimdisi loglar okunurken hata: {e}")
            return

    if not rows:
        return

    # --- AŞAMA 2: Kilit DIŞINDA ağ gönderimi yap ---
    logger.info(f"[OFFLINE->ONLINE] Baglanti saglandi. Bekleyen {len(rows)} log gonderiliyor...")
    sent_ids = []
    for row_id, topic, payload in rows:
        try:
            client.publish(topic, payload, qos=1)
            sent_ids.append(row_id)
        except Exception as e:
            logger.error(f"[OFFLINE] Gonderim hatasi (id={row_id}): {e}")
            break  # Hata olursa kalan logları sonraki denemeye bırak

    if not sent_ids:
        return

    # --- AŞAMA 3: Kilitli bölgede yalnızca başarılı gönderimleri sil ---
    with _offline_db_lock:
        try:
            conn = sqlite3.connect(OFFLINE_DB_PATH, check_same_thread=False)
            cursor = conn.cursor()
            cursor.executemany(
                "DELETE FROM offline_logs WHERE id = ?",
                [(i,) for i in sent_ids]
            )
            conn.commit()
            conn.close()
            logger.info(f"[OFFLINE->ONLINE] {len(sent_ids)} adet cevrimdisi log basariyla gonderildi ve temizlendi.")
        except Exception as e:
            logger.error(f"[OFFLINE] Gonderilen loglar silinirken hata: {e}")

