"""
redis_reconnect.py — Arka planda Redis yeniden bağlantısını deneyen worker.
"""
import time
import app_config as config
from ._base import redis_mgr, logger


def redis_reconnect_worker():
    """Arka planda periyodik olarak Redis'e yeniden bağlanmayı dener.
    Başarılıysa fallback kuyruğundaki verileri Redis'e aktarır."""
    logger.info("[REDIS] Redis Yeniden Baglanti Worker'i aktif.")

    while True:
        time.sleep(config.REDIS_RECONNECT_INTERVAL)
        if redis_mgr.is_redis_active():
            continue  # Zaten bağlı

        logger.debug("[REDIS] Redis kapali, yeniden baglanma deneniyor...")
        success = redis_mgr.try_reconnect()
        if success:
            logger.info("[REDIS] Yeniden baglanti basarili. Tum worker'lar Redis'e geri dondu.")
