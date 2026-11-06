"""
optimization.py — Aktif istemcilerin bant genişliği limitlerini dağıtan worker.
"""
import time
import datetime

import database
from database import SessionLocal, Istemci
from crypto_helper import CryptoHelper
from optimization import get_optimizer
import app_config as config

from ._base import get_token_bucket, logger


def optimization_worker(mqtt_client):
    """Arka planda çalışan, aktif istemcilerin durumuna göre hız limitlerini dağıtan worker."""
    logger.info("[OPTIMIZASYON] Kuresel Bant Genisligi Optimizasyon Calisani aktif.")

    try:
        from optimization.proportional_fair import ProportionalFairOptimizer
        optimizer = ProportionalFairOptimizer()
    except Exception as e:
        logger.error(f"[OPTIMIZASYON] ProportionalFairOptimizer baslatilamadi: {e}")
        optimizer = None
    
    current_optimizer_name = "proportional_fair"

    while True:
        try:
            opt_interval = 60
            global_bw = 2048          # Fallback: 2048 KB/s (DB'den okunamazınca — KB/s biriminde)
            active_opt_name = "proportional_fair"  # Fallback: en hafif algoritma
            
            db = None
            try:
                db = SessionLocal()
                try:
                    cfg = db.query(database.SunucuAyarlari).filter_by(id=1).first()
                    if cfg:
                        opt_interval = cfg.optimization_interval_sec
                        global_bw = cfg.global_max_bandwidth_kbps
                        active_opt_name = cfg.active_optimizer
                    
                    cutoff_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=180)
                    all_clients = db.query(Istemci).all()
                except Exception as db_err:
                    short_err = str(db_err).split("\n")[0]
                    logger.warning(f"[OPTIMIZASYON] Birincil DB baglanti hatasi (PostgreSQL cevrimdisi), SQLite fallback moduna geciliyor: {short_err}")
                    database.fallback_to_sqlite()
                    if db:
                        db.close()
                    db = database.SessionLocal()
                    
                    cfg = db.query(database.SunucuAyarlari).filter_by(id=1).first()
                    if cfg:
                        opt_interval = cfg.optimization_interval_sec
                        global_bw = cfg.global_max_bandwidth_kbps
                        active_opt_name = cfg.active_optimizer
                        
                    cutoff_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=180)
                    all_clients = db.query(Istemci).all()
                    
            except Exception as e:
                logger.error(f"[OPTIMIZASYON] Veritabani okuma hatasi: {e}")
                if db:
                    db.close()
                time.sleep(5)
                continue
            
            # Dinamik optimizer degisimi
            if active_opt_name != current_optimizer_name or optimizer is None:
                try:
                    optimizer = get_optimizer(active_opt_name)
                    current_optimizer_name = active_opt_name
                    logger.info(f"[OPTIMIZASYON] Aktif Optimizasyon Algoritmasi Guncellendi: {active_opt_name.upper()}")
                except Exception as e:
                    logger.error(f"[OPTIMIZASYON] Algoritma '{active_opt_name}' baslatilamadi, oteleme devam ediyor: {e}")

            # DB okuma tamamlandi, baglantiyı sleep öncesinde kapat
            if db:
                db.close()
                db = None

            # Sleep in the loop so it reacts dynamically
            time.sleep(opt_interval)

            # Sleep sonrası taze veriyle istemci listesini al (cutoff_time da burada alınır)
            cutoff_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=180)
            try:
                _db2 = SessionLocal()
                all_clients = _db2.query(Istemci).all()
                _db2.close()
            except Exception as _cl_err:
                logger.error(f"[OPTIMIZASYON] Istemci listesi alinamadi: {_cl_err}")
                continue

            try:
                active_clients_data = []
                for client in all_clients:
                    last_seen = client.son_gorulme
                    if last_seen.tzinfo is None:
                        last_seen = last_seen.replace(tzinfo=datetime.timezone.utc)

                    if last_seen >= cutoff_time:
                        # Önce integer pc_priority kolonunu kullan (queue_worker tarafından güncelleniyor)
                        # Yoksa (eski kayıt) pc_level string'inden fallback yap
                        try:
                            priority = int(client.pc_priority) if client.pc_priority else 5
                        except (ValueError, TypeError):
                            priority = 5
                        if priority == 5:  # pc_priority default ise pc_level'a da bak
                            try:
                                priority = int(client.pc_level)
                            except (ValueError, TypeError):
                                if client.pc_level == "Kritik_Seviye":
                                    priority = 10
                                elif client.pc_level == "Yuksek_Seviye":
                                    priority = 8
                                elif client.pc_level == "Standart_Seviye":
                                    priority = 5

                        active_clients_data.append({
                            "id": client.id,
                            "priority": priority,
                            "risk_score": client.mevcut_puan
                        })

                if not active_clients_data:
                    continue

                # global_bw (KB/s) değerini Byte/s'ye çevir ve havuzun tükenmesini önleyen esnek taban payı belirle
                global_bw_bytes = float(global_bw) * 1024.0
                num_clients = max(len(active_clients_data), 1)
                # Her cihaza asgari garanti: Havuzun %20'sinin eşit payı veya min 64 B/s (darboğazda dahi algoritmaların yarışmasını sağlar)
                min_client_bw = max(64.0, min(256.0, (global_bw_bytes * 0.2) / num_clients))

                allocations = optimizer.allocate(
                    active_clients_data,
                    global_bw_bytes,
                    min_client_bw
                )

                for client_id, alloc in allocations.items():
                    bucket = get_token_bucket(client_id)

                    # Kilitlenmeyi onlemek icin asgari guvence tabani
                    alloc_capacity = max(512.0, float(alloc["capacity"]))
                    alloc_fill_rate = max(64.0, float(alloc["fill_rate"]))

                    if bucket.fill_rate != alloc_fill_rate or bucket.capacity != alloc_capacity:
                        bucket.update_params(capacity=alloc_capacity, fill_rate=alloc_fill_rate)

                        control_topic = f"network/control/{client_id}"
                        cmd = {
                            "action": "UPDATE_LIMITS",
                            "fill_rate": alloc_fill_rate,
                            "capacity": alloc_capacity
                        }
                        encrypted_cmd = CryptoHelper.encrypt_and_compress(cmd)
                        mqtt_client.publish(control_topic, encrypted_cmd, qos=1)
                        logger.info(f"[OPTIMIZASYON] Hiz siniri gonderildi: {client_id} -> Hiz: {alloc_fill_rate / 1024:.1f} KB/s | Kapasite: {alloc_capacity / 1024:.1f} KB")

            except Exception as inner_err:
                logger.error(f"[OPTIMIZASYON] Optimizasyon cevrimi sirasinda ic hata: {inner_err}")

        except Exception as e:
            logger.error(f"[OPTIMIZASYON] Optimization Worker dongu hatasi: {e}")
