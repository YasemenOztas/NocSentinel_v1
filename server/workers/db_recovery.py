"""
db_recovery.py — SQLite fallback verilerini PostgreSQL'e geri taşıyan worker.
"""
import time
import datetime
import logging
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

import database
import app_config as config

from ._base import logger


def db_recovery_worker():
    """SQLite yedek veritabanındaki logları PostgreSQL'e geri taşır ve aktif veritabanını PostgreSQL'e döndürür."""
    logger.info("[DB-RECOVERY] Veritabani Kurtarma ve Senkronizasyon Worker'i aktif.")

    first_run = True
    while True:
        try:
            # Sadece SQLite fallback modundaysak VEYA sunucu yeni açıldığında (ilk döngüde) SQLite'a bakarız
            if database.ACTIVE_DB_URL == database.SQLITE_URL or first_run:
                first_run = False
                sqlite_fallback_engine = create_engine(database.SQLITE_URL)
                TempSqliteSession = sessionmaker(bind=sqlite_fallback_engine)
                sqlite_session = TempSqliteSession()


                try:
                    sqlite_clients    = sqlite_session.query(database.Istemci).all()
                    sqlite_logs       = sqlite_session.query(database.LogKaydi).all()
                    sqlite_sys_events = sqlite_session.query(database.SistemOlaylari).all()

                    # Eski 'loglar' tablosunu kontrol et
                    sqlite_conn = sqlite_fallback_engine.raw_connection()
                    cursor = sqlite_conn.cursor()
                    has_legacy_table = False
                    legacy_logs = []
                    try:
                        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='loglar'")
                        if cursor.fetchone():
                            has_legacy_table = True
                            cursor.execute("SELECT istemci_id, kategori, mesaj, skor, app_name, app_hash, zaman_damgasi FROM loglar")
                            legacy_logs = cursor.fetchall()
                    except Exception as e:
                        logger.error(f"[DB-RECOVERY] Eski 'loglar' tablosu okunurken hata: {e}")
                    finally:
                        sqlite_conn.close()

                    if sqlite_clients or sqlite_logs or legacy_logs or sqlite_sys_events:
                        try:
                            temp_engine = create_engine(database.DATABASE_URL)
                            with temp_engine.connect() as conn:
                                conn.execute(text("SELECT 1"))

                            logger.info("[DB-RECOVERY] Birincil PostgreSQL aktif ve SQLite'ta bekleyen veri var! Senkronizasyon baslatiliyor...")
                            database.Base.metadata.create_all(bind=temp_engine)

                            TempPostgresSession = sessionmaker(bind=temp_engine)
                            pg_session = TempPostgresSession()

                            try:
                                # İstemcileri aktar
                                for c in sqlite_clients:
                                    pg_c = pg_session.query(database.Istemci).filter_by(id=c.id).first()
                                    if not pg_c:
                                        pg_c = database.Istemci(
                                            id=c.id,
                                            ip_adresi=c.ip_adresi,
                                            pc_level=c.pc_level,
                                            mevcut_puan=c.mevcut_puan,
                                            risk_durumu=c.risk_durumu,
                                            son_gorulme=c.son_gorulme
                                        )
                                        pg_session.add(pg_c)
                                    else:
                                        pg_c.mevcut_puan = c.mevcut_puan
                                        pg_c.risk_durumu = c.risk_durumu
                                        pg_c.son_gorulme = c.son_gorulme
                                pg_session.commit()

                                # Logları aktar
                                log_ids = [l.id for l in sqlite_logs]
                                for l in sqlite_logs:
                                    exists = pg_session.query(database.LogKaydi).filter_by(
                                        istemci_id=l.istemci_id,
                                        mesaj=l.mesaj,
                                        zaman_damgasi=l.zaman_damgasi
                                    ).first()
                                    if not exists:
                                        pg_l = database.LogKaydi(
                                            istemci_id=l.istemci_id,
                                            kategori=l.kategori,
                                            mesaj=l.mesaj,
                                            skor=l.skor,
                                            app_name=l.app_name,
                                            app_hash=l.app_hash,
                                            zaman_damgasi=l.zaman_damgasi,
                                            client_create_ts=getattr(l, "client_create_ts", None),
                                            client_send_ts=getattr(l, "client_send_ts", None)
                                        )
                                        pg_session.add(pg_l)
                                pg_session.commit()

                                # Sistem olaylarını aktar
                                sys_event_ids = [s.id for s in sqlite_sys_events]
                                for s in sqlite_sys_events:
                                    exists = pg_session.query(database.SistemOlaylari).filter_by(
                                        olay_tipi=s.olay_tipi,
                                        mesaj=s.mesaj,
                                        zaman_damgasi=s.zaman_damgasi
                                    ).first()
                                    if not exists:
                                        pg_s = database.SistemOlaylari(
                                            kategori=s.kategori,
                                            olay_tipi=s.olay_tipi,
                                            mesaj=s.mesaj,
                                            istemci_id=s.istemci_id,
                                            zaman_damgasi=s.zaman_damgasi
                                        )
                                        pg_session.add(pg_s)
                                pg_session.commit()

                                # Kurtarma tamamlandı kaydı
                                sys_rec_event = database.SistemOlaylari(
                                    kategori="DB",
                                    olay_tipi="DB_RECOVERY",
                                    mesaj="Birincil veritabani tekrar cevrimici! SQLite yedek veritabanindaki veriler basariyla senkronize edildi."
                                )
                                pg_session.add(sys_rec_event)
                                pg_session.commit()

                                # Eski 'loglar' tablosundaki verileri aktar
                                if legacy_logs:
                                    logger.info(f"[DB-RECOVERY] Eski 'loglar' tablosundan {len(legacy_logs)} kayit PostgreSQL'e aktariliyor...")
                                    for row in legacy_logs:
                                        zd = row[6]
                                        if isinstance(zd, str):
                                            try:
                                                zd = datetime.datetime.fromisoformat(zd.replace(" ", "T"))
                                            except Exception:
                                                zd = datetime.datetime.now()
                                        elif not isinstance(zd, datetime.datetime):
                                            zd = datetime.datetime.now()
                                        pg_l = database.LogKaydi(
                                            istemci_id=row[0],
                                            kategori=row[1],
                                            mesaj=row[2],
                                            skor=row[3],
                                            app_name=row[4],
                                            app_hash=row[5],
                                            zaman_damgasi=zd
                                        )
                                        pg_session.add(pg_l)
                                    pg_session.commit()

                                total_migrated = len(sqlite_logs) + len(legacy_logs)
                                logger.info(f"[DB-RECOVERY] {total_migrated} adet fallback log kaydi PostgreSQL'e aktarildi.")

                                # SQLite'ı temizle
                                database.db_lock.acquire()
                                try:
                                    if sqlite_logs:
                                        sqlite_session.query(database.LogKaydi).filter(database.LogKaydi.id.in_(log_ids)).delete(synchronize_session=False)
                                    if sqlite_sys_events:
                                        sqlite_session.query(database.SistemOlaylari).filter(database.SistemOlaylari.id.in_(sys_event_ids)).delete(synchronize_session=False)
                                    sqlite_session.commit()

                                    if has_legacy_table:
                                        sqlite_conn2 = sqlite_fallback_engine.raw_connection()
                                        try:
                                            cursor2 = sqlite_conn2.cursor()
                                            cursor2.execute("DELETE FROM loglar")
                                            sqlite_conn2.commit()
                                        finally:
                                            sqlite_conn2.close()

                                    logger.info("[DB-RECOVERY] SQLite fallback veritabani temizlendi.")

                                    if database.ACTIVE_DB_URL == database.SQLITE_URL:
                                        logger.info("[DB-RECOVERY] Birincil veritabanina geri donuluyor...")
                                        switched = database.switch_db(database.DATABASE_URL)
                                        if switched:
                                            logger.info("[DB-RECOVERY] Sistem artik PostgreSQL uzerinde calisiyor. SQLite fallback modu sona erdi.")
                                        else:
                                            logger.error("[DB-RECOVERY] PostgreSQL'e geri gecis basarisiz! SQLite modunda kalmaya devam ediliyor.")
                                    else:
                                        logger.info("[DB-RECOVERY] Bekleyen SQLite verileri PostgreSQL'e aktarildi, zaten PostgreSQL modundayiz.")
                                except Exception as clean_err:
                                    sqlite_session.rollback()
                                    logger.error(f"[DB-RECOVERY] SQLite temizlenirken hata: {clean_err}")
                                finally:
                                    database.db_lock.release()

                            except Exception as sync_err:
                                logger.error(f"[DB-RECOVERY] Veri gocu sirasinda hata: {sync_err}")
                                pg_session.rollback()
                                sqlite_session.rollback()
                            finally:
                                pg_session.close()

                        except Exception as conn_err:
                            pass  # PostgreSQL henüz geri gelmedi
                finally:
                    sqlite_session.close()

            time.sleep(30)
        except Exception as e:
            logger.error(f"[DB-RECOVERY] DB Recovery Worker dongu hatasi: {e}")
            time.sleep(10)
