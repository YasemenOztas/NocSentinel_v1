from .base import BaseOptimizer

class MaxMinFairOptimizer(BaseOptimizer):
    """
    Max-Min Fairness (Maks-Min Adaleti) tabanlı deterministik bant genişliği dağıtıcısı.
    Su Doldurma (Water-filling) tekniği ile çalışır.
    Düşük öncelikli/yüksek riskli cihazların asgari paylarını garanti eder,
    kalan havuzu talep tavanlarına (priority-weighted demand) göre adilce dağıtır.
    """
    def allocate(self, clients: list, global_max_bandwidth: float, min_client_bandwidth: float) -> dict:
        if not clients:
            return {}

        active_clients = []
        blocked_allocations = {}
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
        reserved_bandwidth = num_active * min_client_bandwidth
        remaining_pool = max(0.0, global_max_bandwidth - reserved_bandwidth)

        # Her aktif cihaz için talep tavanını (demand cap) hesapla.
        # Cihazın önceliği ve riskine göre talep edebileceği maksimum ek bant genişliği payı:
        # demand_cap = remaining_pool * (priority/10) * (1 - risk/100)
        demands = []
        for c in active_clients:
            priority = float(c["priority"])
            risk_score = float(c["risk_score"])
            utility_factor = 1.0 - (risk_score / 100.0)
            
            # Cihazın ek havuzdan isteyeceği maksimum hız (tavan)
            demand_cap = remaining_pool * (priority / 10.0) * utility_factor
            demands.append({
                "id": c["id"],
                "demand": demand_cap,
                "allocated": 0.0
            })

        # Water-filling (Su doldurma) algoritması
        # Talepleri en küçükten en büyüğe doğru sırala
        demands.sort(key=lambda x: x["demand"])
        
        remaining_to_allocate = remaining_pool
        active_count = num_active

        for i, d in enumerate(demands):
            # Kalan havuzun eşit payı
            fair_share = remaining_to_allocate / active_count
            
            # Eğer talep edilen miktar eşit paydan küçükse, sadece talebi kadar ver
            if d["demand"] < fair_share:
                allocation = d["demand"]
            else:
                # Eşit payı ver
                allocation = fair_share
                
            d["allocated"] = allocation
            remaining_to_allocate -= allocation
            active_count -= 1

        # Eğer hala artan havuz varsa (tüm talepler karşılandığı halde), 
        # kalan miktarı orantılı olarak en yüksek önceliklilere dağıt
        if remaining_to_allocate > 0.01:
            total_allocated = sum(d["allocated"] for d in demands)
            if total_allocated > 0:
                for d in demands:
                    ratio = d["allocated"] / total_allocated
                    d["allocated"] += remaining_to_allocate * ratio
            else:
                # Eşit dağıt
                share = remaining_to_allocate / num_active
                for d in demands:
                    d["allocated"] += share

        # Sonuçları formatla
        result = {}
        for d in demands:
            b_val = min_client_bandwidth + d["allocated"]
            result[d["id"]] = {
                "fill_rate": round(b_val, 2),
                "capacity": round(max(min_client_bandwidth, b_val * 2.0), 2)
            }
        result.update(blocked_allocations)
        return result
