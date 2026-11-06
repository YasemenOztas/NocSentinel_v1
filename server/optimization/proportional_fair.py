from .base import BaseOptimizer

class ProportionalFairOptimizer(BaseOptimizer):
    """
    Orantılı Adil Paylaşım (Proportional Fair) tabanlı küresel bant genişliği dağıtıcısı.
    Deterministik, kararlı ve O(N) zaman karmaşıklığıyla çalışır.
    """
    def allocate(self, clients: list, global_max_bandwidth: float, min_client_bandwidth: float) -> dict:
        if not clients:
            return {}

        active_clients = []
        blocked_allocations = {}

        # 1. Aşama: Tamamen bloke olması gereken (Risk >= 90) cihazları ayır.
        for c in clients:
            if c["risk_score"] >= 90.0:
                blocked_allocations[c["id"]] = {
                    "fill_rate": 0.0,
                    "capacity": min_client_bandwidth
                }
            else:
                active_clients.append(c)

        if not active_clients:
            return blocked_allocations

        num_active = len(active_clients)
        
        # Asgari rezerve edilen bant genişliği
        reserved_bandwidth = num_active * min_client_bandwidth
        remaining_pool = max(0.0, global_max_bandwidth - reserved_bandwidth)

        # 2. Aşama: Her cihazın orantı ağırlığını hesapla (Priority & Risk tabanlı)
        # Ağırlık = Öncelik * (1.0 - Risk/100.0)
        client_weights = []
        total_weight = 0.0
        
        for c in active_clients:
            priority = float(c["priority"])
            risk_score = float(c["risk_score"])
            
            # Risk faktörüne göre ağırlığı düzelt
            weight = priority * (1.0 - (risk_score / 100.0))
            client_weights.append((c["id"], weight))
            total_weight += weight

        # 3. Aşama: Kalan havuzu orantılı olarak dağıt
        result = {}
        if total_weight == 0.0:
            # Eşit paylaşım fallback
            share = remaining_pool / num_active
            for c in active_clients:
                b_val = min_client_bandwidth + share
                result[c["id"]] = {
                    "fill_rate": round(b_val, 2),
                    "capacity": round(max(min_client_bandwidth, b_val * 2.0), 2)
                }
        else:
            for cid, w in client_weights:
                share_ratio = w / total_weight
                b_val = min_client_bandwidth + (remaining_pool * share_ratio)
                result[cid] = {
                    "fill_rate": round(b_val, 2),
                    "capacity": round(max(min_client_bandwidth, b_val * 2.0), 2)
                }

        # Engellenenleri ekle
        result.update(blocked_allocations)
        return result
