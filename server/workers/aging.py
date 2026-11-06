"""
aging.py — Kuyruktaki logların önceliğini artıran (aging) worker.
Starvation problemini önler: eski loglar skor küçülerek öne çıkar.
"""
import time
import app_config as config
from ._base import redis_mgr, logger


def aging_worker():
    """Arka planda periyodik olarak çalışan log yaşlandırma (aging) worker."""
    logger.info("[AGING] Log Yaslandirma (Aging) Worker'i aktif.")

    while True:
        try:
            time.sleep(config.AGING_INTERVAL)
            _r = redis_mgr.get()
            if redis_mgr.is_redis_active():
                # Redis ZSET aging
                try:
                    logs = _r.zrange(config.REDIS_LOG_KEY, 0, -1, withscores=True)
                    if logs:
                        pipe = _r.pipeline()
                        for log_bytes, score in logs:
                            new_score = score - 2.0
                            pipe.zadd(config.REDIS_LOG_KEY, {log_bytes: new_score})
                        pipe.execute()
                        logger.debug("[AGING] Redis ZSET log yaslama cevrimi tamamlandi.")
                except Exception as redis_err:
                    try:
                        import redis as _redis_lib
                        if isinstance(redis_err, (_redis_lib.ConnectionError, _redis_lib.TimeoutError,
                                                  ConnectionRefusedError, OSError)):
                            redis_mgr.mark_failed()
                        else:
                            logger.error(f"[AGING] Redis aging hatasi: {redis_err}")
                    except ImportError:
                        redis_mgr.mark_failed()
            else:
                # Fallback in-memory kuyruk yaşlandırma
                with _r._lock:
                    if config.REDIS_LOG_KEY in _r._zsets:
                        for m in list(_r._zsets[config.REDIS_LOG_KEY].keys()):
                            _r._zsets[config.REDIS_LOG_KEY][m] -= 2.0
                        logger.debug("[AGING] Fallback ZSET log yaslama cevrimi tamamlandi.")
        except Exception as e:
            logger.error(f"[AGING] Aging worker hatasi: {e}")
