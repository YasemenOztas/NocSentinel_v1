"""
_base.py — Workers paketinin temel modülü.

Paylaşılan durum (shared state), yardımcı sınıflar ve fabrika fonksiyonları
burada tanımlanır. Hiçbir alt worker modülünü import ETMEZ; böylece dairesel
import riski sıfıra iner. Tüm worker modülleri bu dosyadan import yapar.
"""
import os
import redis
import sys
import time
import logging
import threading

# Yol yapılandırması (workers/_base.py → server/ → Yaso_Deneme/ → common/)
_workers_dir = os.path.dirname(os.path.abspath(__file__))   # server/workers/
_server_dir  = os.path.dirname(_workers_dir)                # server/
_common_dir  = os.path.join(os.path.dirname(_server_dir), "common")

for _p in (_server_dir, _common_dir):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import app_config as config
from token_bucket import TokenBucket

logger = logging.getLogger("ServerWorkers")

# ======================= VERİ AKIŞ SAYAÇLARI =======================
class ThroughputStats:
    """Sunucu throughput (veri akışı) istatistiklerini tutan thread-safe sınıf."""
    def __init__(self):
        self.total_bytes = 0
        self.dropped_packets = 0
        self.lock = threading.Lock()

stats = ThroughputStats()

# ======================= JETON KOVALARI =======================
client_buckets = {}
_buckets_lock = threading.Lock()

# ======================= COOLDOWN ZAMANLAYICILARI =======================
ACTIVE_COOLDOWNS = {}
COOLDOWN_EVENTS = {}
_cooldowns_lock = threading.Lock()

def get_token_bucket(client_id: str) -> TokenBucket:
    """Her istemci için ayrı ve risk-duyarlı jeton kovası döner."""
    with _buckets_lock:
        if client_id not in client_buckets:
            client_buckets[client_id] = TokenBucket()
        return client_buckets[client_id]

# ======================= REDIS VE FALLBACK KUYRUK =======================
class _FallbackQueue:
    """Redis çevrimdışı olduğunda bellek üzerinde çalışan ZSET ve Liste fallback kuyruğu."""
    def __init__(self):
        self._zsets = {}
        self._lists = {}
        self._plain = {}
        self._lock = threading.Lock()

    def zadd(self, key, mapping):
        with self._lock:
            if key not in self._zsets:
                self._zsets[key] = {}
            for m, s in mapping.items():
                self._zsets[key][m] = s

    def zpopmin(self, key, count=1):
        with self._lock:
            if key not in self._zsets or not self._zsets[key]:
                return []
            sorted_items = sorted(self._zsets[key].items(), key=lambda x: x[1])
            res = sorted_items[:count]
            for m, s in res:
                del self._zsets[key][m]
            return res

    def zremrangebyscore(self, key, min_score, max_score):
        with self._lock:
            if key not in self._zsets:
                return
            to_del = [m for m, s in self._zsets[key].items() if min_score <= s <= max_score]
            for m in to_del:
                del self._zsets[key][m]

    def lpush(self, key, value):
        with self._lock:
            if key not in self._lists:
                self._lists[key] = []
            self._lists[key].insert(0, value)

    def brpop(self, key, timeout=0):
        deadline = time.time() + (timeout if timeout else 999999)
        while time.time() < deadline:
            with self._lock:
                if key in self._lists and self._lists[key]:
                    return (key, self._lists[key].pop())
            time.sleep(0.1)
        return None

    def zcard(self, key):
        with self._lock:
            return len(self._zsets.get(key, {}))

    def zrange(self, key, start, stop, withscores=False):
        with self._lock:
            if key not in self._zsets:
                return []
            sorted_items = sorted(self._zsets[key].items(), key=lambda x: x[1])
            if stop == -1:
                sliced = sorted_items[start:]
            else:
                sliced = sorted_items[start:stop + 1]
            if withscores:
                return [(m, s) for m, s in sliced]
            return [m for m, s in sliced]

    def get(self, key):
        with self._lock:
            return self._plain.get(key)

    def set(self, key, value):
        with self._lock:
            self._plain[key] = value

    def hset(self, key, mapping=None, **kwargs):
        with self._lock:
            if key not in self._plain or not isinstance(self._plain.get(key), dict):
                self._plain[key] = {}
            if mapping:
                self._plain[key].update(
                    {k.encode() if isinstance(k, str) else k: v for k, v in mapping.items()}
                )
            for k, v in kwargs.items():
                self._plain[key][k.encode()] = v

    def hmset(self, key, mapping):
        self.hset(key, mapping=mapping)

    def hgetall(self, key):
        with self._lock:
            stored = self._plain.get(key, {})
            if isinstance(stored, dict):
                return dict(stored)
            return {}

    def ping(self):
        return True

    def pipeline(self):
        return _FallbackPipeline(self)


class _FallbackPipeline:
    def __init__(self, queue):
        self._q = queue
        self._cmds = []

    def zincrby(self, key, amount, member):
        self._cmds.append(("zincrby", key, amount, member))
        return self

    def zadd(self, key, mapping):
        self._cmds.append(("zadd", key, mapping))
        return self

    def execute(self):
        with self._q._lock:
            for cmd in self._cmds:
                if cmd[0] == "zincrby":
                    if cmd[1] not in self._q._zsets:
                        self._q._zsets[cmd[1]] = {}
                    self._q._zsets[cmd[1]][cmd[3]] = self._q._zsets[cmd[1]].get(cmd[3], 0) + cmd[2]
                elif cmd[0] == "zadd":
                    key, mapping = cmd[1], cmd[2]
                    if key not in self._q._zsets:
                        self._q._zsets[key] = {}
                    self._q._zsets[key].update(mapping)
        self._cmds.clear()


# ======================= REDIS BAĞLANTI YÖNETİCİSİ =======================

class RedisConnectionManager:
    """Redis bağlantısını merkezi olarak yöneten, arıza/kurtarma geçişlerini
    thread-safe biçimde koordine eden sınıf."""

    def __init__(self):
        self._lock = threading.Lock()
        self._active: object = None
        self._is_redis: bool = False
        self._failure_logged: bool = False
        self._fallback = _FallbackQueue()  # Kalıcı fallback nesnesi (veri kaybını önler)
        self._init()

    def _init(self):
        """Başlangıçta Redis'e bağlanmayı dener; olmazsa fallback'e geçer."""
        try:
            client = redis.Redis(
                host=config.REDIS_HOST,
                port=config.REDIS_PORT,
                db=config.REDIS_DB,
                password=config.REDIS_PASSWORD if config.REDIS_PASSWORD else None,
                socket_timeout=config.REDIS_SOCKET_TIMEOUT,
                socket_connect_timeout=config.REDIS_SOCKET_TIMEOUT,
            )
            client.ping()
            self._active = client
            self._is_redis = True
            logger.info("[REDIS] Baglanti basarili. Oncelikli kuyruk (ZSET) aktif.")
        except Exception as e:
            logger.warning(
                f"[REDIS] Baslangic baglanti hatasi: {e}. "
                "In-memory fallback devrede — sistem calismaya devam edecek."
            )
            self._active = self._fallback
            self._is_redis = False

    def get(self):
        with self._lock:
            return self._active

    def is_redis_active(self) -> bool:
        with self._lock:
            return self._is_redis

    def mark_failed(self):
        """Redis bağlantısı koptu sinyali. Flood önleme ile tek seferlik log."""
        with self._lock:
            if not self._is_redis:
                return
            if not self._failure_logged:
                logger.warning(
                    "[REDIS] Baglanti koptu! In-memory fallback kuyruğuna geçildi. "
                    "Redis reconnect worker arka planda yeniden bağlanmayı deniyor..."
                )
                self._failure_logged = True
            self._active = self._fallback
            self._is_redis = False

    def try_reconnect(self) -> bool:
        """Redis'e yeniden bağlanmayı dener, başarılıysa fallback verisini flush eder."""
        try:
            import redis as _redis
            client = _redis.Redis(
                host=config.REDIS_HOST,
                port=config.REDIS_PORT,
                db=0,
                socket_timeout=config.REDIS_SOCKET_TIMEOUT,
                socket_connect_timeout=config.REDIS_SOCKET_TIMEOUT,
            )
            client.ping()
        except Exception:
            return False

        with self._lock:
            if self._is_redis:
                return True  # Başka thread zaten reconnect yaptı

            old_fallback = self._active
            migrated_zset = 0
            migrated_list = 0

            try:
                if isinstance(old_fallback, _FallbackQueue):
                    with old_fallback._lock:
                        for key, members in old_fallback._zsets.items():
                            if members:
                                client.zadd(key, members)
                                migrated_zset += len(members)
                        for key, items in old_fallback._lists.items():
                            for item in reversed(items):
                                client.lpush(key, item)
                                migrated_list += 1
            except Exception as flush_err:
                logger.error(f"[REDIS] Fallback veri aktarimi sirasinda hata: {flush_err}")

            self._active = client
            self._is_redis = True
            self._failure_logged = False

        logger.info(
            f"[REDIS] Yeniden baglandi! Fallback'ten aktarilan: "
            f"{migrated_zset} ZSET girisi, {migrated_list} LIST girisi."
        )
        try:
            import database
            db = database._SessionMaker()
            event = database.SistemOlaylari(
                kategori="SISTEM",
                olay_tipi="REDIS_RECOVERY",
                mesaj=(
                    f"Redis yeniden baglandi. Fallback'ten aktarilan: "
                    f"{migrated_zset} ZSET, {migrated_list} LIST girisi."
                ),
            )
            db.add(event)
            db.commit()
            db.close()
        except Exception:
            pass

        return True


# Modül düzeyinde tekil yönetici nesnesi
redis_mgr = RedisConnectionManager()

# Geriye dönük uyumluluk: diğer modüller (risk_engine, receiver_server)
# hâlâ `r` adıyla erişiyor; bu alias onları kırmadan çalışmaya devam ettirir.
r = redis_mgr.get()

# Test dosyalarında kullanılan Redis bağlantı durum bayrağı
REDIS_AVAILABLE = redis_mgr.is_redis_active()

