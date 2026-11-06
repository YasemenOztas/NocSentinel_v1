"""
registry.py — Merkezi Callback/Event Kayıt Defteri (Callback Registry Pattern)

Dairesel import (circular import) sorununu çözmek için tasarlanmıştır.
Modüller birbirini doğrudan import etmek yerine bu merkezi kayıt üzerinden haberleşir.

Kullanım — Kayıt (genellikle modül başlatıldığında):
    from registry import CallbackRegistry
    CallbackRegistry.register("send_whitelist", send_whitelist_to_client)

Kullanım — Tetikleme (başka modülden):
    from registry import CallbackRegistry
    CallbackRegistry.trigger("send_whitelist", pc_name)

Kayıt Olmayan Event:
    Kayıtlı olmayan bir event tetiklenirse RuntimeError fırlatılır.
    Sessiz başarısızlık yerine güvenli-başarısızlık (fail-safe) davranışı sağlanır.
"""

import logging

logger = logging.getLogger("CallbackRegistry")


class CallbackRegistry:
    """
    Global, thread-unsafe kayıt defteri.

    Not: Kayıt (register) işlemleri tipik olarak uygulama başlangıcında
    tek thread'de gerçekleştiğinden ayrı bir lock eklenmemiştir.
    Çok thread'li kayıt gerekirse _lock eklenmelidir.
    """
    _callbacks: dict = {}

    @classmethod
    def register(cls, event_name: str, callback_fn):
        """
        Bir event adına callback fonksiyonu kaydeder.
        Aynı isimde kayıt varsa üzerine yazar ve uyarı loglar.
        """
        if event_name in cls._callbacks:
            logger.warning(
                f"[REGISTRY] '{event_name}' event'i icin mevcut kayit uzerine yazildi."
            )
        cls._callbacks[event_name] = callback_fn
        logger.debug(f"[REGISTRY] '{event_name}' event'i kaydedildi -> {callback_fn.__name__}")

    @classmethod
    def trigger(cls, event_name: str, *args, **kwargs):
        """
        Kayıtlı callback'i çağırır ve sonucunu döndürür.

        Hata Durumu:
            Kayıtlı değilse RuntimeError fırlatılır.
        """
        if event_name not in cls._callbacks:
            raise RuntimeError(
                f"[REGISTRY] Kayitli olmayan event tetiklendi: '{event_name}'. "
                f"Mevcut kayitlar: {list(cls._callbacks.keys())}"
            )
        return cls._callbacks[event_name](*args, **kwargs)

    @classmethod
    def is_registered(cls, event_name: str) -> bool:
        """Event'in kayıtlı olup olmadığını kontrol eder (tetiklemeden önce güvenlik kontrolü için)."""
        return event_name in cls._callbacks

    @classmethod
    def unregister(cls, event_name: str):
        """Bir event kaydını siler (temizlik / test senaryoları için)."""
        if event_name in cls._callbacks:
            del cls._callbacks[event_name]
            logger.debug(f"[REGISTRY] '{event_name}' event kaydı silindi.")
