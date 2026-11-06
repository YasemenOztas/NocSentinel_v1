import random
import math
from .base import BaseOptimizer

class SimulatedAnnealingOptimizer(BaseOptimizer):
    """
    Tavlama Benzetimi (Simulated Annealing - SA) tabanlı küresel bant genişliği dağıtıcısı.
    Tekil-nokta araması yapar, yerel minimumlardan kurtulmak için olasılıksal kabul uygular.
    """
    def __init__(self, init_temp=100.0, cooling_rate=0.95, min_temp=0.01, steps_per_temp=10):
        self.init_temp = init_temp
        self.cooling_rate = cooling_rate
        self.min_temp = min_temp
        self.steps_per_temp = steps_per_temp

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

        def decode(weights):
            sum_w = sum(weights)
            allocations = {}
            if sum_w == 0:
                share = remaining_pool / num_active
                for c in active_clients:
                    allocations[c["id"]] = min_client_bandwidth + share
            else:
                for idx, c in enumerate(active_clients):
                    weight = weights[idx] / sum_w
                    allocations[c["id"]] = min_client_bandwidth + (remaining_pool * weight)
            return allocations

        def calculate_fitness(weights):
            allocations = decode(weights)
            score_sum = 0.0
            for c in active_clients:
                b_i = allocations[c["id"]]
                priority = float(c["priority"])
                risk_score = float(c["risk_score"])
                utility_factor = 1.0 - (risk_score / 100.0)
                score_sum += b_i * priority * utility_factor
            return score_sum

        # Başlangıç çözümü
        current_sol = [random.random() for _ in range(num_active)]
        current_fit = calculate_fitness(current_sol)
        
        best_sol = current_sol.copy()
        best_fit = current_fit
        
        temp = self.init_temp

        # SA Ana Döngüsü
        while temp > self.min_temp:
            for _ in range(self.steps_per_temp):
                # Komşu aday üret
                candidate = current_sol.copy()
                # Rastgele bir elemanı hafifçe değiştir
                idx = random.randint(0, num_active - 1)
                candidate[idx] = max(0.0, min(1.0, candidate[idx] + random.uniform(-0.1, 0.1)))
                
                candidate_fit = calculate_fitness(candidate)
                delta_e = candidate_fit - current_fit
                
                # Eğer daha iyiyse veya olasılık dahilindeyse kabul et
                if delta_e > 0:
                    current_sol = candidate
                    current_fit = candidate_fit
                else:
                    # Olasılıksal kabul (Metropolis kriteri)
                    # delta_e negatif olduğu için e^(delta_e / temp) hesaplanır
                    try:
                        p = math.exp(delta_e / temp)
                    except OverflowError:
                        p = 0.0
                    if random.random() < p:
                        current_sol = candidate
                        current_fit = candidate_fit
                
                # En iyi çözümü kaydet
                if current_fit > best_fit:
                    best_fit = current_fit
                    best_sol = current_sol.copy()
            
            # Sıcaklığı düşür
            temp *= self.cooling_rate

        best_allocations = decode(best_sol)
        result = {}
        for cid, b_val in best_allocations.items():
            result[cid] = {
                "fill_rate": round(b_val, 2),
                "capacity": round(max(min_client_bandwidth, b_val * 2.0), 2)
            }
        result.update(blocked_allocations)
        return result
