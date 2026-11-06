import random
from .base import BaseOptimizer

class PSOOptimizer(BaseOptimizer):
    """
    Parçacık Sürü Optimizasyonu (Particle Swarm Optimization - PSO) tabanlı küresel bant genişliği dağıtıcısı.
    """
    def __init__(self, swarm_size=30, max_iter=60, w=0.5, c1=1.5, c2=1.5):
        self.swarm_size = swarm_size
        self.max_iter = max_iter
        self.w = w
        self.c1 = c1
        self.c2 = c2

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

        def decode(position):
            sum_p = sum(position)
            allocations = {}
            if sum_p == 0:
                share = remaining_pool / num_active
                for c in active_clients:
                    allocations[c["id"]] = min_client_bandwidth + share
            else:
                for idx, c in enumerate(active_clients):
                    weight = position[idx] / sum_p
                    allocations[c["id"]] = min_client_bandwidth + (remaining_pool * weight)
            return allocations

        def calculate_fitness(position):
            allocations = decode(position)
            score_sum = 0.0
            for c in active_clients:
                b_i = allocations[c["id"]]
                priority = float(c["priority"])
                risk_score = float(c["risk_score"])
                utility_factor = 1.0 - (risk_score / 100.0)
                score_sum += b_i * priority * utility_factor
            return score_sum

        # Sürü ilklendir
        positions = [[random.random() for _ in range(num_active)] for _ in range(self.swarm_size)]
        velocities = [[random.uniform(-0.1, 0.1) for _ in range(num_active)] for _ in range(self.swarm_size)]
        
        pbest = [pos.copy() for pos in positions]
        pbest_fitness = [calculate_fitness(pos) for pos in positions]
        
        gbest = positions[pbest_fitness.index(max(pbest_fitness))].copy()
        gbest_fitness = max(pbest_fitness)

        # PSO Ana Döngüsü
        for itr in range(self.max_iter):
            for i in range(self.swarm_size):
                for j in range(num_active):
                    r1 = random.random()
                    r2 = random.random()
                    
                    velocities[i][j] = (self.w * velocities[i][j] + 
                                        self.c1 * r1 * (pbest[i][j] - positions[i][j]) + 
                                        self.c2 * r2 * (gbest[j] - positions[i][j]))
                    velocities[i][j] = max(-0.2, min(0.2, velocities[i][j]))
                    positions[i][j] = max(0.0, min(1.0, positions[i][j] + velocities[i][j]))

                fit = calculate_fitness(positions[i])
                
                if fit > pbest_fitness[i]:
                    pbest_fitness[i] = fit
                    pbest[i] = positions[i].copy()
                    
                if fit > gbest_fitness:
                    gbest_fitness = fit
                    gbest = positions[i].copy()

        best_allocations = decode(gbest)
        result = {}
        for cid, b_val in best_allocations.items():
            result[cid] = {
                "fill_rate": round(b_val, 2),
                "capacity": round(max(min_client_bandwidth, b_val * 2.0), 2)
            }
        result.update(blocked_allocations)
        return result
