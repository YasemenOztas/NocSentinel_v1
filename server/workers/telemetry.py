"""
telemetry.py — Redis listesinden donanım telemetri verilerini çekip DB'ye kaydeden worker.
"""
import time
import datetime
import msgpack

import database
from database import SessionLocal, Istemci
import app_config as config

from ._base import redis_mgr, r, logger


def telemetry_worker():
    """Redis listesinden telemetri verilerini çekip veritabanına yazar."""
    logger.info("[WORKER] Donanim Telemetri Worker'i aktif.")

    while True:
        try:
            _r = redis_mgr.get()
            try:
                packed_tel = _r.brpop(config.REDIS_TELEMETRY_KEY, timeout=2)
            except Exception as redis_err:
                try:
                    import redis as _redis_lib
                    if isinstance(redis_err, (_redis_lib.ConnectionError, _redis_lib.TimeoutError,
                                              _redis_lib.BusyLoadingError, ConnectionRefusedError, OSError)):
                        redis_mgr.mark_failed()
                    else:
                        logger.error(f"[TELEMETRI] Redis hatasi: {redis_err}")
                except ImportError:
                    redis_mgr.mark_failed()
                time.sleep(2)
                continue

            if packed_tel:
                tel_bytes = packed_tel[1]
                tel_data  = msgpack.unpackb(tel_bytes, raw=False)

                pc_name = tel_data["pc_name"]
                cpu     = tel_data["cpu_percent"]
                ram     = tel_data["ram_percent"]
                temp    = tel_data["cpu_temp"]

                # Telemetriyi hızlı erişim için Redis'e kaydet (SIEM AI korelasyonu)
                try:
                    redis_mgr.get().hset(f"telemetry:{pc_name}", mapping={"cpu": cpu, "ram": ram, "temp": temp})
                except Exception as redis_tel_err:
                    logger.debug(f"[TELEMETRI] Redis'e kaydedilemedi: {redis_tel_err}")

                def run_telemetry_transaction():
                    db = SessionLocal()
                    try:
                        db_client = db.query(Istemci).filter_by(id=pc_name).first()
                        if not db_client:
                            db_client = Istemci(id=pc_name, mevcut_puan=0.0)
                            db.add(db_client)
                        db_client.son_gorulme = datetime.datetime.now(datetime.timezone.utc)
                        db.commit()
                        logger.debug(f"[TELEMETRI] Guncellendi: {pc_name} | CPU: %{cpu} | RAM: %{ram}")
                    except Exception as tel_db_err:
                        db.rollback()
                        raise tel_db_err
                    finally:
                        db.close()

                try:
                    database.db_lock.acquire()
                    run_telemetry_transaction()
                except Exception as e:
                    logger.debug(f"[TELEMETRI] Veritabanı hatasi, telemetri atlandi: {e}")
                    try:
                        if database.ACTIVE_DB_URL != database.SQLITE_URL:
                            database.fallback_to_sqlite()
                    except Exception:
                        pass
                finally:
                    database.db_lock.release()
        except Exception as e:
            logger.error(f"[WORKER] Telemetry Worker dongu hatasi: {e}")
            time.sleep(2)
