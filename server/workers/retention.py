import time
import datetime
import sqlalchemy
from sqlalchemy import create_engine
import database
from database import SessionLocal, LogKaydi
from ._base import logger

RETENTION_DAYS = 30
CHECK_INTERVAL = 3600  # Her saat başı kontrol et

def retention_worker():
    """Arka planda periyodik olarak veritabanı boyutunu korumak için eski logları siler."""
    logger.info(f"[RETENTION] Log temizleme Worker'i aktif ({RETENTION_DAYS} gunluk periyot).")
    
    while True:
        try:
            # Hemen ilk başta çok az bekle ve başlat, sonra saatlik bekle
            cutoff_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=RETENTION_DAYS)
            
            # 1. Ana Veritabanı (Postgres) Temizliği
            db = SessionLocal()
            try:
                deleted_main = db.query(LogKaydi).filter(LogKaydi.zaman_damgasi < cutoff_date).delete(synchronize_session=False)
                db.commit()
                if deleted_main > 0:
                    logger.info(f"[RETENTION] Ana DB'den {deleted_main} adet eski log silindi.")
            except Exception as e:
                logger.error(f"[RETENTION] Ana DB temizleme hatasi: {e}")
                db.rollback()
            finally:
                db.close()
                
            # 2. Fallback (SQLite) Temizliği
            try:
                sqlite_fallback_engine = create_engine(database.SQLITE_URL)
                with sqlite_fallback_engine.begin() as conn:
                    cutoff_str = cutoff_date.isoformat()
                    stmt = sqlalchemy.text("DELETE FROM log_kayitlari WHERE zaman_damgasi < :cutoff")
                    result = conn.execute(stmt, {"cutoff": cutoff_str})
                    deleted_fallback = result.rowcount
                    if deleted_fallback > 0:
                        logger.info(f"[RETENTION] Fallback DB'den {deleted_fallback} adet eski log silindi.")
            except Exception as e:
                logger.error(f"[RETENTION] Fallback DB temizleme hatasi: {e}")

        except Exception as err:
            logger.error(f"[RETENTION] Beklenmeyen hata: {err}")

        time.sleep(CHECK_INTERVAL)
