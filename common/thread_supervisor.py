"""
thread_supervisor.py — Hata Toleranslı Thread Gözetmeni (Supervisor Pattern)

Kullanım:
    from thread_supervisor import supervise_thread
    supervise_thread(my_function, args=(arg1, arg2), name="MyThread")

Thread beklenmedik bir hatayla çökerse:
- Hata loglanır (exc_info ile tam stack trace)
- `restart_delay` saniye beklenir
- Thread otomatik olarak yeniden başlatılır

Thread normal şekilde sonlanırsa (return ile çıkarsa) yeniden BAŞLATILMAZ.
Bu davranış, kasıtlı kapatma senaryolarıyla çakışmaması için tasarlanmıştır.
"""

import time
import logging
import threading

logger = logging.getLogger("Supervisor")


def supervise_thread(target_fn, args=(), kwargs=None, name=None, restart_delay=5):
    """
    Hedef fonksiyonu gözetim altında arka plan thread'i olarak çalıştırır.

    Parametreler
    ------------
    target_fn     : Çalıştırılacak fonksiyon.
    args          : Pozisyonel argümanlar (tuple).
    kwargs        : Anahtar kelime argümanları (dict).
    name          : Thread için gösterilecek isim (log mesajlarında kullanılır).
    restart_delay : Çökme sonrası yeniden başlatma bekleme süresi (saniye, varsayılan 5).

    Dönüş
    ------
    Başlatılmış threading.Thread nesnesi.
    """
    kwargs = kwargs or {}
    thread_name = name or target_fn.__name__

    def run_wrapper():
        while True:
            try:
                logger.info(f"[SUPERVISOR] Thread '{thread_name}' baslatiliyor...")
                target_fn(*args, **kwargs)
                # Fonksiyon normal return ile sonlandı — yeniden başlatma
                logger.info(f"[SUPERVISOR] Thread '{thread_name}' normal sekilde sonlandi. Yeniden baslatilmiyor.")
                break
            except Exception as e:
                logger.error(
                    f"[SUPERVISOR] Thread '{thread_name}' beklenmedik sekilde coktu! "
                    f"Hata: {e}",
                    exc_info=True
                )
                logger.info(
                    f"[SUPERVISOR] Thread '{thread_name}' {restart_delay} saniye icinde yeniden baslatilacak..."
                )
                time.sleep(restart_delay)

    t = threading.Thread(target=run_wrapper, name=thread_name, daemon=True)
    t.start()
    return t
