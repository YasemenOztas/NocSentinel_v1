import time

class TokenBucket:
    """
    Sunucu (Server) tarafı için Risk-Duyarlı Jeton Kovası Algoritması.
    Tehlike altındaki istemcileri kısıtlamak amacıyla risk skoruna göre dolum hızını dinamik olarak düşürür.
    """
    def __init__(self, capacity=2 * 1024 * 1024, fill_rate=2 * 1024 * 1024):
        self.capacity = float(capacity)   # Maksimum birikim (Byte)
        self.tokens = float(capacity)     # Mevcut jeton miktarı (Byte)
        self.fill_rate = float(fill_rate) # Saniyede eklenen jeton (Byte/sn)
        self.last_update = time.time()

    def consume(self, packet_size: int, risk_score: float = 0.0) -> bool:
        """
        Jeton tüketmeye çalışır.
        Risk skoru arttıkça dolum hızı düşer (Risk-Adaptive Token Bucket):
        - Risk = 0   -> %100 Hız (2 MB/sn)
        - Risk = 50  -> %50 Hız (1 MB/sn)
        - Risk >= 100 -> %0 Hız (Tamamen Engellendi)
        """
        now = time.time()
        delta = now - self.last_update
        self.last_update = now

        # Risk faktörünü hesaba katarak dolum hızını azalt (istemciden farkı burası)
        performance_factor = max(0.0, 1.0 - (risk_score / 100.0))
        current_fill_rate = self.fill_rate * performance_factor

        self.tokens = min(self.capacity, self.tokens + (current_fill_rate * delta))

        if self.tokens >= packet_size:
            self.tokens -= packet_size
            return True
        else:
            return False

    def update_params(self, capacity=None, fill_rate=None):
        """Kapasite ve hızı dinamik olarak günceller."""
        if capacity is not None:
            self.capacity = float(capacity)
            self.tokens = min(self.tokens, self.capacity)
        if fill_rate is not None:
            self.fill_rate = float(fill_rate)
