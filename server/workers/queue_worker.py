"""
queue_worker.py — Redis ZSET kuyruğundan log çekip DB'ye kaydeden worker.
"""
import time
import datetime
import logging
import threading
import msgpack

import database
from database import SessionLocal, Istemci, LogKaydi, SistemOlaylari
from crypto_helper import CryptoHelper
from risk_engine import RiskEngine
import app_config as config

from ._base import redis_mgr, r, ACTIVE_COOLDOWNS, COOLDOWN_EVENTS, _cooldowns_lock, logger

def queue_worker(mqtt_client):
    """Redis ZSET kuyruğundan logları toplu (batch) çekip veritabanına kaydeder ve Risk Engine çalıştırır."""
    logger.info("[WORKER] Log isleme Worker'i (Priority ZSET - Batch Modu) aktif.")

    while True:
        try:
            _r = redis_mgr.get()
            try:
                # Redis'ten tek seferde en fazla 25 log çek
                log_items = _r.zpopmin(config.REDIS_LOG_KEY, count=25)
            except Exception as redis_err:
                try:
                    import redis as _redis_lib
                    if isinstance(redis_err, (_redis_lib.ConnectionError, _redis_lib.TimeoutError,
                                              _redis_lib.BusyLoadingError, ConnectionRefusedError, OSError)):
                        redis_mgr.mark_failed()
                    else:
                        logger.error(f"[WORKER] Queue Worker Redis hatasi: {redis_err}")
                except ImportError:
                    redis_mgr.mark_failed()
                time.sleep(1)
                continue

            if log_items:
                _active_r = redis_mgr.get()

                def run_batch_transaction():
                    db = SessionLocal()
                    try:
                        processed_clients = {}

                        # YENİ: Test modu kontrolü — batch başına bir kez okunur.
                        # False ise risk skoru/aksiyon HESAPLANIP LogKaydi'ye
                        # yazılmaya devam eder (analiz/makale verisi için), ama
                        # gerçek BLOCK_APP/RESTRICT/ISOLATE/LOCKDOWN komutları
                        # istemciye gönderilmez ve cooldown/RECOVER thread'i
                        # başlatılmaz. Bkz. SunucuAyarlari.security_actions_enabled.
                        _server_cfg = db.query(database.SunucuAyarlari).filter_by(id=1).first()
                        actions_enabled = (
                            _server_cfg.security_actions_enabled if _server_cfg is not None else True
                        )
                        if not actions_enabled:
                            logger.info("[TEST MODU] security_actions_enabled=False — aksiyonlar hesaplanıp loglanıyor, komut gönderilmiyor.")

                        for log_bytes, score_val in log_items:
                            try:
                                log_data = msgpack.unpackb(log_bytes, raw=False)
                            except Exception:
                                continue

                            pc_name     = log_data["pc_name"]
                            pc_priority = log_data["pc_priority"]
                            log_level   = log_data["log_level"]
                            log_priority= log_data["log_priority"]
                            message     = log_data["message"]
                            app_name    = log_data["app_name"]
                            app_hash    = log_data["app_hash"]
                            # YENİ: Gerçek gecikme/kısıtlama ölçümü için istemci taraflı
                            # zaman damgaları (sender_agent.py'de eklendi). Eski istemciler
                            # (henüz güncellenmemiş) bu alanları göndermez -> .get() ile
                            # None'a düşer, get_scenario_metrics tarafında zaten bu durum
                            # (eksik veri -> tahmini formüle geri dönüş) ele alınıyor.
                            client_create_ts = log_data.get("client_create_ts")
                            client_send_ts   = log_data.get("client_send_ts")

                            if pc_name not in processed_clients:
                                db_client = db.query(Istemci).filter_by(id=pc_name).first()
                                if not db_client:
                                    db_client = Istemci(id=pc_name, mevcut_puan=0.0)
                                    db.add(db_client)
                                    db.flush()
                                processed_clients[pc_name] = db_client
                            else:
                                db_client = processed_clients[pc_name]

                            risk_assessment = RiskEngine.calculate_risk(
                                pc_priority=pc_priority,
                                log_priority=log_priority,
                                log_level=log_level,
                                app_hash=app_hash,
                                app_name=app_name,
                                message=message,
                                pc_name=pc_name,
                                r=_active_r,
                                db=db
                            )
                            new_risk_score = risk_assessment["risk_score"]
                            action         = risk_assessment["action"]
                            is_blocked     = risk_assessment["is_blocked"]

                            db_client.mevcut_puan = new_risk_score
                            db_client.risk_durumu = (action in ["ISOLATE", "LOCKDOWN", "RESTRICT"]) if actions_enabled else False
                            db_client.son_gorulme = datetime.datetime.now(datetime.timezone.utc)
                            db_client.pc_level    = str(pc_priority)
                            db_client.pc_priority = int(pc_priority)  # YENİ: get_policy() doğru öncelikle çalışsın

                            log_action = action
                            if is_blocked:
                                log_action = f"BLOCK_APP + {action}" if action != "ALLOW" else "BLOCK_APP"

                            new_log_entry = LogKaydi(
                                istemci_id=pc_name,
                                kategori=log_level,
                                mesaj=message,
                                skor=new_risk_score,
                                aksiyon=log_action,
                                app_name=app_name,
                                app_hash=app_hash,
                                client_create_ts=client_create_ts,  # YENİ
                                client_send_ts=client_send_ts       # YENİ
                            )
                            db.add(new_log_entry)

                            # Otomatik aksiyon kararını SistemOlaylari tablosuna kaydet
                            # (test modunda bile kaydedilir — sadece komut gönderimi atlanır)
                            if action != "ALLOW" or is_blocked:
                                action_desc = f"Otomatik Karar: {action}"
                                if is_blocked:
                                    action_desc += f" | Surec Sonlandirma: {app_name} ({app_hash[:16]}...)"
                                if not actions_enabled:
                                    action_desc += " | [TEST MODU - KOMUT GONDERILMEDI]"
                                try:
                                    sys_event = SistemOlaylari(
                                        kategori="GUVENLIK",
                                        olay_tipi="OTOMATIK_AKSIYON",
                                        mesaj=action_desc,
                                        istemci_id=pc_name
                                    )
                                    db.add(sys_event)
                                except Exception as sys_err:
                                    logger.error(f"[WORKER] SistemOlaylari ekleme hatasi: {sys_err}")

                            # Süreç Kapatma (BLOCK_APP) — test modunda GÖNDERİLMEZ
                            if is_blocked:
                                if actions_enabled:
                                    control_topic = f"network/control/{pc_name}"
                                    cmd = {"action": "BLOCK_APP", "app_hash": app_hash, "app_name": app_name}
                                    encrypted_cmd = CryptoHelper.encrypt_and_compress(cmd)
                                    mqtt_client.publish(control_topic, encrypted_cmd, qos=1)
                                    logger.warning(f"[AKSIYON] Cihaza surec sonlandirma komutu gonderildi: {pc_name} -> BLOCK_APP ({app_name})")
                                else:
                                    logger.info(f"[TEST MODU - AKSİYON ENGELLENDİ] {pc_name} için BLOCK_APP ({app_name}) komutu istemciye GÖNDERİLMEDİ.")

                            # Host Seviyesinde Kısıtlama / Karantina — test modunda GÖNDERİLMEZ
                            # (RESTRICT özellikle önemli: optimizer'ın dışından fill_rate
                            # değiştirdiği için bant genişliği testini kirletir)
                            if action in ["ISOLATE", "LOCKDOWN", "RESTRICT"]:
                                if not actions_enabled:
                                    logger.info(f"[TEST MODU - AKSİYON ENGELLENDİ] {pc_name} için hesaplanan '{action}' kararı istemciye GÖNDERİLMEDİ (Algoritma Test Modu Aktif).")
                                else:
                                    control_topic = f"network/control/{pc_name}"
                                    cmd = {"action": action, "app_hash": app_hash, "app_name": app_name}
                                    encrypted_cmd = CryptoHelper.encrypt_and_compress(cmd)
                                    mqtt_client.publish(control_topic, encrypted_cmd, qos=1)
                                    logger.warning(f"[AKSIYON] Cihaza host karantina komutu gonderildi: {pc_name} -> {action}")

                                from risk_engine import get_policy
                                policy = get_policy(db_client.pc_priority if db_client.pc_priority else 5)
                                duration = 0
                                if action == "RESTRICT":
                                    duration = db_client.restrict_duration if db_client.restrict_duration is not None else policy["restrict_duration_sec"]
                                elif action == "ISOLATE":
                                    duration = db_client.isolate_duration if db_client.isolate_duration is not None else policy["isolate_duration_sec"]
                                elif action == "LOCKDOWN":
                                    duration = db_client.lockdown_duration if db_client.lockdown_duration is not None else policy["lockdown_duration_sec"]

                                if duration > 0:
                                    should_start_thread = True
                                    with _cooldowns_lock:
                                        if pc_name in ACTIVE_COOLDOWNS and ACTIVE_COOLDOWNS[pc_name] > time.time():
                                            should_start_thread = False
                                        else:
                                            if pc_name in COOLDOWN_EVENTS:
                                                COOLDOWN_EVENTS[pc_name].set()
                                            event = threading.Event()
                                            COOLDOWN_EVENTS[pc_name] = event
                                            ACTIVE_COOLDOWNS[pc_name] = time.time() + duration

                                    if should_start_thread:
                                        def delayed_recover(_name=pc_name, _dur=duration, _ev=event):
                                            is_cancelled = _ev.wait(timeout=_dur)
                                            if is_cancelled:
                                                logger.info(f"[COOLDOWN] Cooldown thread'i iptal edildi: {_name}")
                                                return
                                            with _cooldowns_lock:
                                                target_time = ACTIVE_COOLDOWNS.get(_name, 0)
                                            if target_time > time.time() + 0.1:
                                                return

                                            logger.info(f"[COOLDOWN] Karantina suresi doldu ({_dur}sn). {_name} icin RECOVER komutu gonderiliyor...")
                                            recover_cmd = {"action": "RECOVER"}
                                            enc_recover = CryptoHelper.encrypt_and_compress(recover_cmd)
                                            mqtt_client.publish(f"network/control/{_name}", enc_recover, qos=1)

                                            db_rec = SessionLocal()
                                            try:
                                                sys_event = database.SistemOlaylari(
                                                    kategori="COOLDOWN",
                                                    olay_tipi="COOLDOWN_EXPIRED",
                                                    mesaj=f"Karantina suresi doldu ({_dur}sn). Cihaz otomatik kurtarildi.",
                                                    istemci_id=_name
                                                )
                                                db_rec.add(sys_event)
                                                cli_rec = db_rec.query(database.Istemci).filter_by(id=_name).first()
                                                if cli_rec:
                                                    cli_rec.risk_durumu = False
                                                    cli_rec.mevcut_puan = 0.0
                                                db_rec.commit()
                                            except Exception as db_err:
                                                logger.error(f"[COOLDOWN] DB hatasi: {db_err}")
                                                db_rec.rollback()
                                            finally:
                                                db_rec.close()

                                        t = threading.Thread(target=delayed_recover, daemon=True)
                                        t.start()

                        # Toplu kaydı veritabanına TEK İŞLEM (1 Transaction) olarak işle!
                        db.commit()
                        logger.info(f"[WORKER] {len(log_items)} adet log veritabanina toplu (batch) kaydedildi.")

                    except Exception as trans_err:
                        logger.error(f"[WORKER] Kuyruk toplu veri islemi DB hatasi: {trans_err}")
                        db.rollback()
                        raise trans_err
                    finally:
                        db.close()

                try:
                    database.db_lock.acquire()
                    run_batch_transaction()
                except Exception as run_err:
                    short_err = str(run_err).split("\n")[0]
                    logger.critical(f"[DB-FALLBACK] Birincil DB hatasi! SQLite yedegine geciliyor: {short_err}")
                    try:
                        database.fallback_to_sqlite()
                        db_fb = database._SessionMaker()
                        try:
                            for log_bytes, _ in log_items:
                                try:
                                    log_data = msgpack.unpackb(log_bytes, raw=False)
                                    new_fb_log = LogKaydi(
                                        istemci_id=log_data["pc_name"],
                                        kategori=log_data["log_level"],
                                        mesaj=log_data["message"],
                                        skor=50.0,
                                        app_name=log_data["app_name"],
                                        app_hash=log_data["app_hash"],
                                        client_create_ts=log_data.get("client_create_ts"),  # YENİ
                                        client_send_ts=log_data.get("client_send_ts")       # YENİ
                                    )
                                    db_fb.add(new_fb_log)
                                except Exception:
                                    pass
                            db_fb.commit()
                            logger.info(f"[DB-FALLBACK] {len(log_items)} adet log SQLite yedegine toplu yazildi.")
                        except Exception as sql_err:
                            db_fb.rollback()
                            logger.error(f"[DB-FALLBACK] SQLite yedegine yazilirken hata: {sql_err}")
                        finally:
                            db_fb.close()
                    except Exception as fb_err:
                        logger.error(f"[DB-FALLBACK] Fallback sureci baslatilirken kritik hata: {fb_err}")
                finally:
                    database.db_lock.release()
            else:
                time.sleep(0.05)
        except Exception as e:
            logger.error(f"[WORKER] Queue Worker dongu hatasi: {e}")
            time.sleep(0.5)