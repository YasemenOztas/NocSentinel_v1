from abc import ABC, abstractmethod

class BaseOptimizer(ABC):
    """
    Tüm bant genişliği optimizasyon algoritmaları için temel soyut sınıf (Interface).
    """
    @abstractmethod
    def allocate(self, clients: list, global_max_bandwidth: float, min_client_bandwidth: float) -> dict:
        """
        Bant genişliği dağılımını hesaplar.
        
        Args:
            clients: İstemci bilgilerini içeren liste:
                     [
                         {
                             "id": str,          # Cihaz Adı
                             "priority": int,    # Cihaz Önceliği (1-10)
                             "risk_score": float # Dinamik Risk Skoru (0-100)
                         }, ...
                     ]
            global_max_bandwidth: Sunucu toplam bant genişliği limiti (Byte/sn)
            min_client_bandwidth: İstemci başına asgari hız sınırı (Byte/sn)
            
        Returns:
            dict: {client_id: { "fill_rate": float, "capacity": float }} formatında dağılım.
        """
        pass
