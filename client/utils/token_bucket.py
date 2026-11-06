import time

# Fiziksel ağ kapasitesinin donanımsal üst sınırı (2MB/sn).
# Sunucudan ne kadar büyük bir limit emri gelse de bu değer asla aşılamaz.
_HARD_CAP_BYTES = 2 * 1024 * 1024  # 2 MB/sn

class TokenBucket:
    """
    İstemci (Client) tarafı için sade Jeton Kovası Algoritması.
    Risk puanından bağımsız olarak sadece kendisine atanan kapasite ve hıza göre kısıtlama yapar.
    Kapasite ve dolum hızı hiçbir koşulda _HARD_CAP_BYTES değerini aşamaz.
    """
    def __init__(self, capacity=2 * 1024 * 1024, fill_rate=2 * 1024 * 1024):
        self.capacity = float(min(capacity, _HARD_CAP_BYTES))   # Maksimum birikim (Byte)
        self.tokens = float(self.capacity)                        # Mevcut jeton miktarı (Byte)
        self.fill_rate = float(min(fill_rate, _HARD_CAP_BYTES))  # Saniyede eklenen jeton (Byte/sn)
        self.last_update = time.time()

    def consume(self, packet_size: int) -> bool:
        """Jeton tüketmeye çalışır. Yeterli jeton varsa True, yoksa False döner."""
        now = time.time()
        delta = now - self.last_update
        self.last_update = now

        # Jetonları doldur
        self.tokens = min(self.capacity, self.tokens + (self.fill_rate * delta))

        if self.tokens >= packet_size:
            self.tokens -= packet_size
            return True
        else:
            return False

    def update_params(self, capacity=None, fill_rate=None):
        """Kapasite ve hızı dinamik olarak günceller. Hard-cap sınırı aşılamaz."""
        if capacity is not None:
            self.capacity = float(min(capacity, _HARD_CAP_BYTES))
            self.tokens = min(self.tokens, self.capacity)
        if fill_rate is not None:
            self.fill_rate = float(min(fill_rate, _HARD_CAP_BYTES))
