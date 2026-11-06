"""
workers/__init__.py — Workers paketi dış arayüzü.

Mevcut kodun ``from workers import X`` ve ``import workers`` çağrıları
hiçbir değişiklik yapılmadan çalışmaya devam eder.
Tüm paylaşımlı state (_base.py) ve worker fonksiyonları buradan re-export edilir.
"""

# Dış bağımlılıklar ve uyumluluk için
import database
from database import SessionLocal

# Paylaşılan state ve yardımcı öğeler
from ._base import (
    redis_mgr,
    r,
    stats,
    get_token_bucket,
    client_buckets,
    _buckets_lock,
    ACTIVE_COOLDOWNS,
    COOLDOWN_EVENTS,
    _cooldowns_lock,
    ThroughputStats,
    RedisConnectionManager,
    _FallbackQueue,
    _FallbackPipeline,
    REDIS_AVAILABLE,
    logger,
)

# Worker fonksiyonları
from .queue_worker    import queue_worker
from .telemetry       import telemetry_worker
from .db_recovery     import db_recovery_worker
from .aging           import aging_worker
from .traffic         import throughput_reporter
from .optimization    import optimization_worker
from .redis_reconnect import redis_reconnect_worker
from .retention       import retention_worker

__all__ = [
    # Uyumluluk
    "database", "SessionLocal", "REDIS_AVAILABLE",
    # State
    "redis_mgr", "r", "stats", "get_token_bucket",
    "client_buckets", "_buckets_lock",
    "ACTIVE_COOLDOWNS", "COOLDOWN_EVENTS", "_cooldowns_lock",
    "ThroughputStats", "RedisConnectionManager", "logger",
    # Workers
    "queue_worker", "telemetry_worker", "db_recovery_worker",
    "aging_worker", "throughput_reporter", "optimization_worker",
    "redis_reconnect_worker", "retention_worker",
]


