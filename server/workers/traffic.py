"""
traffic.py — Periyodik ağ trafiği hız raporlayıcısı.
"""
import time
import app_config as config
from ._base import stats, logger


def throughput_reporter():
    """Her TRAFFIC_REPORT_INTERVAL saniyede bir sunucunun toplam veri hızını (KB/sn) ekrana yazar."""
    logger.info("[TRAFIK] Ag Trafigi Hiz Raporlayicisi aktif.")
    last_time = time.time()

    while True:
        time.sleep(config.TRAFFIC_REPORT_INTERVAL)
        try:
            now = time.time()
            elapsed = now - last_time
            last_time = now

            with stats.lock:
                bps  = stats.total_bytes / elapsed
                kbps = bps / 1024.0
                dropped = stats.dropped_packets
                stats.total_bytes = 0
                stats.dropped_packets = 0

            logger.info(f"[TRAFIK] Ag Giris Hizi: {kbps:.2f} KB/sn | Drop Edilen Paket (Son {config.TRAFFIC_REPORT_INTERVAL}sn): {dropped}")
        except Exception as e:
            logger.error(f"[TRAFIK] Traffic reporter hatasi: {e}")
