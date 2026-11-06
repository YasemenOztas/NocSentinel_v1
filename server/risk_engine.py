import logging
import time
import threading
from sqlalchemy.orm import Session

try:
    import app_config as config
except ImportError:
    try:
        import common.app_config as config
    except ImportError:
        config = None

try:
    import database
    from database import KaraListe, BeyazListe, OncelikPolitikalari
except ImportError:
    from .database import KaraListe, BeyazListe, OncelikPolitikalari

logger = logging.getLogger("RiskEngine")

# ======================= POLITIKA ONBELLEGI (In-Memory Cache) =======================
# Sunucu basladiktan sonra DB'den yuklenir; admin panelinden guncelleme gelince
# hem DB hem bu sozluk guncellenir. Her log geldiginde DB'ye gitmez, RAM'dan okur.

_policy_cache: dict = {}
_policy_cache_lock = threading.RLock()
# Varsayilan politika: DB'ye erisim yoksa kullanilir (config.py'deki eski degerler)
_DEFAULT_POLICY = {
    "restrict_duration_sec": 1800,
    "isolate_duration_sec": 900,
    "lockdown_duration_sec": 600,
    "telemetry_interval_sec": 30,
    "risk_threshold_restrict": 55.0,
    "risk_threshold_isolate": 80.0,
    "risk_threshold_lockdown": 90.0,
    "min_bandwidth_kbps": 5,
    "ai_analysis_enabled": True,
    "auto_isolate_exempt": False,
}

def load_policy_cache(db: Session = None) -> None:
    """Oncelik politikalarini veritabanindan yukleyerek RAM onbellegini doldurur.
    Sunucu baslarken ve admin panelinden bir politika guncellendikten sonra cagirilir.
    """
    global _policy_cache
    if db is None:
        try:
            db = database.SessionLocal()
            _load_and_close = True
        except Exception:
            logger.warning("[POLITIKA] DB baglantisi kurulamadi, varsayilan politikalar kullanilacak.")
            return
    else:
        _load_and_close = False

    try:
        rows = db.query(OncelikPolitikalari).all()
        new_cache = {}
        for row in rows:
            new_cache[row.priority_level] = {
                "restrict_duration_sec":  row.restrict_duration_sec,
                "isolate_duration_sec":   row.isolate_duration_sec,
                "lockdown_duration_sec":  row.lockdown_duration_sec,
                "telemetry_interval_sec": row.telemetry_interval_sec,
                "risk_threshold_restrict":  row.risk_threshold_restrict,
                "risk_threshold_isolate":   row.risk_threshold_isolate,
                "risk_threshold_lockdown":  row.risk_threshold_lockdown,
                "min_bandwidth_kbps":     row.min_bandwidth_kbps,
                "ai_analysis_enabled":    row.ai_analysis_enabled,
                "auto_isolate_exempt":    row.auto_isolate_exempt,
            }
        with _policy_cache_lock:
            _policy_cache = new_cache
        logger.info(f"[POLITIKA] {len(new_cache)} oncelik seviyesi RAM onbellegine yuklendi.")
    except Exception as e:
        logger.error(f"[POLITIKA] Politikalar yuklenirken hata: {e}")
    finally:
        if _load_and_close:
            db.close()

def get_policy(priority_level: int) -> dict:
    """Verilen oncelik seviyesi icin politikayi dondurur. Bulunamazsa en yakin seviyeyi veya varsayilani dondurur."""
    with _policy_cache_lock:
        if priority_level in _policy_cache:
            return _policy_cache[priority_level]
        # Tam eslesme bulunamazsa en yakin seviyeyi bul
        if _policy_cache:
            closest = min(_policy_cache.keys(), key=lambda k: abs(k - priority_level))
            return _policy_cache[closest]
    return _DEFAULT_POLICY


class RiskEngine:
    """
    Windows Event Logs, PC öncelikleri ve yasaklı uygulama tespitlerini
    birleştirerek 100 üzerinden dinamik bir Risk Skoru hesaplar.
    """

    @staticmethod
    def evaluate_siem_correlation(message: str, log_level: str, log_priority: int,
                                  telemetry_data: dict, recent_events: list,
                                  pc_priority: int, pc_name: str = "Unknown") -> dict:
        """AI API kullanarak çok vektörlü siber korelasyon gerçekleştirir.
        AI sağlayıcısı .env dosyasındaki AI_API_BASE ve AI_API_MODEL ile belirlenir.
        """
        import app_config as config
        url = f"{config.AI_API_BASE.rstrip('/')}/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {config.AI_API_KEY}",
            "Content-Type": "application/json"
        }

        cpu  = telemetry_data.get("cpu", 0.0)
        ram  = telemetry_data.get("ram", 0.0)
        temp = telemetry_data.get("temp", 0.0)
        
        system_prompt = (
            "Sen merkezi bir SIEM Risk Analiz Yapay Zekasısın. Sana bir uç noktanın (PC) "
            "önem derecesini, donanım kaynak tüketimini (CPU, RAM, Temp), son 5 dakikadaki log geçmişini "
            "ve yeni gelen olayı iletiyorum. Bu verileri korelasyonlu bir şekilde analiz ederek 0 ile 100 arasında "
            "kalibre edilmiş bir Risk Skoru (`risk_score`) ve Türkçe gerekçe (`reason`) üret.\n\n"
            "ÖNEMLİ DEĞERLENDİRME ESASLARI:\n"
            "1. Sıradan işletim sistemi veya geliştirici süreçlerinin (conhost.exe, docker.exe, msedge.exe, svchost.exe vb.) "
            "başlatılması veya tek başına yüksek RAM/CPU kullanımı GERÇEK BİR SİBER TEHDİT DEĞİLDİR (Risk Skoru 0 - 35 aralığında kalmalıdır).\n"
            "2. Şüpheli durumlar (Başarısız oturum açmalar, yeni servis/kullanıcı ekleme vb.) orta risk skoru üretir (40 - 70 aralığı).\n"
            "3. Kritik tehditler (Event Log silinmesi, zararlı/ransomware süreci, kaba kuvvet saldırısı) yüksek risk skoru üretir (75 - 100 aralığı).\n\n"
            "Yanıtını sadece ve sadece aşağıdaki şablonu dolduracak şekilde, geçerli bir JSON objesi olarak dön. "
            "Asla JSON dışında açıklama veya metin ekleme.\n\n"
            "ŞABLON:\n"
            "{\n"
            "  \"risk_score\": 0 ile 100 arasında tamsayı,\n"
            "  \"reason\": \"Kısa Türkçe korelasyon analizi gerekçesi\"\n"
            "}"
        )
        
        user_prompt = (
            f"Uç Nokta: {pc_name}\n"
            f"PC Öncelik Derecesi: {pc_priority}/10\n"
            f"Donanım Durumu: CPU: %{cpu} | RAM: %{ram} | Sıcaklık: {temp}C\n"
            f"Log Seviyesi: {log_level} | Log Önceliği: {log_priority}\n"
            f"Yeni Gelen Olay: {message}\n"
            f"Son 5 Dakikalık Olay Günlüğü Geçmişi:\n" + "\n".join(recent_events)
        )
        
        payload = {
            "model": config.AI_API_MODEL,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.1
        }
        
        try:
            import requests
            import json
            response = requests.post(url, headers=headers, json=payload, timeout=6)
            if response.status_code == 200:
                result = response.json()
                content = result["choices"][0]["message"]["content"]
                parsed = json.loads(content)
                return {
                    "risk_score": float(parsed.get("risk_score", 0.0)),
                    "reason": str(parsed.get("reason", "SIEM AI risk analizi tamamlandı."))
                }
            else:
                raise ConnectionError(f"HTTP Status: {response.status_code}")
        except Exception as e:
            logger.warning(f"[SIEM-AI-ERROR] Korelasyon API hatası ({e}). Otonom kurallara geçiliyor.")
            return None

    @staticmethod
    def calculate_risk(
        pc_priority: int,
        log_priority: int,
        log_level: str,
        app_hash: str,
        app_name: str,
        message: str = None,
        pc_name: str = "Unknown",
        r = None,
        db: Session = None
    ) -> dict:
        # 1. Kara Liste Kontrolu — Oncelik kapsami sirasina gore sorgu
        # Oncelik: 1) Cihaz bazli kural (device_scope_id) -> 2) Oncelik bazli (priority_scope) -> 3) Global (ikisi de NULL)
        blocked_app = None
        is_blocked = False
        hash_risk = 0.0
        if db:
            for query_filter in [
                # 1) Cihaz bazli eslesme (en guclu)
                lambda q, h, n: q.filter(
                    (KaraListe.device_scope_id == pc_name) &
                    ((KaraListe.hash_sha256 == h) | KaraListe.islem_adi.ilike(n))
                ).first() if h and h != "Unknown" or n and n != "Unknown" else None,
                # 2) Oncelik bazli eslesme
                lambda q, h, n: q.filter(
                    (KaraListe.priority_scope == pc_priority) &
                    (KaraListe.device_scope_id.is_(None)) &
                    ((KaraListe.hash_sha256 == h) | KaraListe.islem_adi.ilike(n))
                ).first() if h and h != "Unknown" or n and n != "Unknown" else None,
                # 3) Global kural (kapsam yok)
                lambda q, h, n: q.filter(
                    KaraListe.priority_scope.is_(None) &
                    KaraListe.device_scope_id.is_(None) &
                    ((KaraListe.hash_sha256 == h) | KaraListe.islem_adi.ilike(n))
                ).first() if h and h != "Unknown" or n and n != "Unknown" else None,
            ]:
                try:
                    result = query_filter(db.query(KaraListe), app_hash or "", app_name or "")
                    if result:
                        blocked_app = result
                        break
                except Exception:
                    continue

        if blocked_app:
            hash_risk = float(blocked_app.risk_puani)
            is_blocked = True
            logger.warning(f"[OTONOM-KORUMA] Kara listedeki yasakli uygulama tespit edildi! Surec: {app_name} | Hash: {str(app_hash)[:16]}... | Ceza: +{hash_risk}")

        # 2. Windows Event ID Kontrolleri (Güvenlik Politikası Cezaları)
        event_id_penalty = 0.0
        event_id_action = None
        if message and "Windows Event ID:" in message:
            try:
                parts = message.split("|")
                id_part = parts[0].replace("Windows Event ID:", "").strip()
                event_id = int(id_part)
                
                if event_id in [1100, 1102]:
                    event_id_penalty = 100.0
                    event_id_action = "LOCKDOWN"
                    logger.critical(f"[OTONOM-KORUMA] EventID={event_id} | Security Gunlugu silindi veya durduruldu! LOCKDOWN emri tetikleniyor.")
                elif event_id == 4720:
                    event_id_penalty = 40.0
                    logger.warning(f"[GUVENLIK] EventID=4720 | {pc_name} uzerinde yeni kullanici hesabi olusturuldu. | Ceza: +40")
                elif event_id == 4732:
                    event_id_penalty = 50.0
                    logger.warning(f"[GUVENLIK] EventID=4732 | {pc_name} uzerinde Administrators grubuna yetki yukseltme algilandi. | Ceza: +50")
                elif event_id == 4625:
                    now = time.time()
                    redis_key = f"failed_logons:{pc_name}"
                    if r:
                        r.zadd(redis_key, {str(now): now})
                        r.zremrangebyscore(redis_key, float('-inf'), now - 60)
                        failed_count = r.zcard(redis_key)
                        logger.warning(f"[GUVENLIK] EventID=4625 | {pc_name} | Son 1 dakikada basarisiz giris sayisi: {failed_count}")
                        if failed_count >= 5:
                            event_id_penalty = 80.0
                            event_id_action = "ISOLATE"
                            logger.critical(f"[BRUTEFORCE] EventID=4625 | 5+ basarisiz deneme! Cihaz izole ediliyor. | Ceza: +80")
                        else:
                            event_id_penalty = failed_count * 10.0
            except Exception as ev_err:
                logger.error(f"Event ID otonom kontrol hatasi: {ev_err}")

        # 3. ÇOK VEKTÖRLÜ SIEM AI KORELASYONU
        # AI etkinligi artik politika onbelleginden okunur
        corr_res = None
        try:
            from database import SunucuAyarlari
            cfg = db.query(SunucuAyarlari).filter_by(id=1).first()
            global_ai = cfg.global_ai_enabled if cfg else True
        except:
            global_ai = True
            
        policy = get_policy(pc_priority)
        use_ai_env = getattr(config, "USE_AI_ANALYSIS", True) if config else True
        ai_enabled = use_ai_env and policy.get("ai_analysis_enabled", True) and global_ai
        
        if ai_enabled:
            cpu, ram, temp = 0.0, 0.0, 0.0
            if r and pc_name:
                try:
                    tel_stored = r.hgetall(f"telemetry:{pc_name}")
                    if tel_stored:
                        cpu = float(tel_stored.get(b"cpu", b"0"))
                        ram = float(tel_stored.get(b"ram", b"0"))
                        temp = float(tel_stored.get(b"temp", b"0"))
                except Exception:
                    pass
                    
            import datetime
            from database import LogKaydi
            recent_events = []
            if db and pc_name:
                try:
                    five_minutes_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)
                    recent_logs = db.query(LogKaydi).filter(
                        LogKaydi.istemci_id == pc_name,
                        LogKaydi.zaman_damgasi >= five_minutes_ago
                    ).order_by(LogKaydi.zaman_damgasi.desc()).limit(10).all()
                    for log in recent_logs:
                        recent_events.append(f"[{log.kategori}] {log.mesaj} (Skor: {log.skor})")
                except Exception as e:
                    logger.error(f"[KORELASYON] Log gecmisi sorgulanirken hata: {e}")
            
            corr_res = RiskEngine.evaluate_siem_correlation(
                message=message,
                log_level=log_level,
                log_priority=log_priority,
                telemetry_data={"cpu": cpu, "ram": ram, "temp": temp},
                recent_events=recent_events,
                pc_priority=pc_priority,
                pc_name=pc_name
            )

        if ai_enabled and corr_res:
            ai_score  = float(corr_res.get("risk_score", 0.0))
            ai_reason = corr_res.get("reason", "")

            # Toplam Risk = AI Analiz Skoru, Event ID cezası ve Kara liste riskinin maksimumu
            total_risk = max(ai_score, event_id_penalty, hash_risk)
            if is_blocked and hash_risk >= 90:
                total_risk = 100.0
                event_id_action = "LOCKDOWN"
                logger.critical("[KARALISTE] Kritik tehdit: Zararli yazilim tespiti! LOCKDOWN emri tetikleniyor.")

            total_risk = max(0.0, min(100.0, total_risk))

            # Aksiyon Belirleme — Cihazın Öncelik Seviyesine Özel Dinamik Eşikler!
            t_lockdown  = policy.get("risk_threshold_lockdown", 90.0)
            t_isolate   = policy.get("risk_threshold_isolate",  80.0)
            t_restrict  = policy.get("risk_threshold_restrict", 55.0)
            auto_exempt = policy.get("auto_isolate_exempt", False)

            if event_id_action:
                final_action = event_id_action
            elif log_level.upper() == "EMERGENCY" or total_risk >= t_lockdown:
                final_action = "ISOLATE" if auto_exempt else "LOCKDOWN"
            elif total_risk >= t_isolate:
                final_action = "RESTRICT" if auto_exempt else "ISOLATE"
            elif total_risk >= t_restrict:
                final_action = "RESTRICT"
            else:
                final_action = "ALLOW"

            logger.info(
                f"[SIEM-KORELASYON] Karar: RiskSkoru={total_risk:.1f}/100 | "
                f"Aksiyon={final_action} (Eşikler [Lvl {pc_priority}]: R:{t_restrict}/I:{t_isolate}/L:{t_lockdown}) | "
                f"Gerekce: {ai_reason}"
            )
            return {
                "risk_score": total_risk,
                "action": final_action,
                "is_blocked": is_blocked
            }

        # 4. YEREL YEDEK YONETMELIGi (AI kapaliysS veya API basarisizsa)
        # Esikler artik config.py hardcoded degil, politika onbelleginden okunuyor!
        log_level_penalty = 0.0
        level_upper = log_level.upper()
        if level_upper == "EMERGENCY":
            log_level_penalty = 40.0
        elif level_upper == "CRITICAL":
            log_level_penalty = 30.0
        elif level_upper == "WARNING":
            log_level_penalty = 15.0
            
        base_score = float(pc_priority * log_priority)
        total_risk = (base_score * 0.3) + (log_level_penalty * 0.7) + (hash_risk * 1.0) + (event_id_penalty * 0.8)
        
        if is_blocked and hash_risk >= 90:
            total_risk = 100.0
            event_id_action = "LOCKDOWN"
            logger.critical("[KARALISTE] Kritik tehdit: WannaCry/Ransomware suspesi! LOCKDOWN emri tetikleniyor.")
        
        total_risk = max(0.0, min(100.0, total_risk))

        # Aksiyon Belirleme — Dinamik Esikler (Politika Onbelleginden)
        t_lockdown = policy.get("risk_threshold_lockdown", 90.0)
        t_isolate  = policy.get("risk_threshold_isolate",  80.0)
        t_restrict = policy.get("risk_threshold_restrict", 55.0)
        auto_exempt = policy.get("auto_isolate_exempt", False)

        if event_id_action:
            action = event_id_action
            # auto_isolate_exempt dahi olsa EventID LOCKDOWN/ISOLATE'ini ezemeyiz (guvenlik geregi)
        elif log_level.upper() == "EMERGENCY" or total_risk >= t_lockdown:
            action = "ISOLATE" if auto_exempt else "LOCKDOWN"
        elif total_risk >= t_isolate:
            action = "RESTRICT" if auto_exempt else "ISOLATE"
        elif total_risk >= t_restrict:
            action = "RESTRICT"
        else:
            action = "ALLOW"

        logger.info(f"[KARAR] RiskSkoru={total_risk:.1f}/100 | Aksiyon={action} | is_blocked={is_blocked} | PC_Priority={pc_priority} | Esikler=({t_restrict}/{t_isolate}/{t_lockdown})")
        return {
            "risk_score": round(total_risk, 1),
            "action": action,
            "is_blocked": is_blocked
        }
