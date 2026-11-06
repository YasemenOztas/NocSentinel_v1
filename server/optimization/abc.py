import random
from .base import BaseOptimizer

class ABCOptimizer(BaseOptimizer):
    """
    Yapay Arı Kolonisi (Artificial Bee Colony - ABC) tabanlı küresel bant genişliği dağıtıcısı.
    """
    def __init__(self, colony_size=30, limit=10, max_iter=80):
        self.colony_size = colony_size
        self.food_number = colony_size // 2
        self.limit = limit
        self.max_iter = max_iter

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

        # İlklendirme
        foods = [[random.random() for _ in range(num_active)] for _ in range(self.food_number)]
        fitness = [calculate_fitness(f) for f in foods]
        trial = [0] * self.food_number

        best_food = foods[fitness.index(max(fitness))].copy()
        best_fitness = max(fitness)

        # ABC Ana Döngüsü
        for itr in range(self.max_iter):
            # Employed Bees
            for i in range(self.food_number):
                param_to_change = random.randint(0, num_active - 1)
                k = random.choice([x for x in range(self.food_number) if x != i]) if self.food_number > 1 else i
                phi = random.uniform(-1, 1)
                candidate = foods[i].copy()
                candidate[param_to_change] = max(0.0, min(1.0, candidate[param_to_change] + phi * (foods[i][param_to_change] - foods[k][param_to_change])))
                
                candidate_fitness = calculate_fitness(candidate)
                if candidate_fitness > fitness[i]:
                    foods[i] = candidate
                    fitness[i] = candidate_fitness
                    trial[i] = 0
                else:
                    trial[i] += 1

            # Onlooker Bees
            sum_fit = sum(fitness)
            prob = [f / sum_fit if sum_fit > 0 else 1.0 / self.food_number for f in fitness]
            for _ in range(self.food_number):
                r_val = random.random()
                cumulative = 0.0
                selected_index = 0
                for idx, p_val in enumerate(prob):
                    cumulative += p_val
                    if r_val <= cumulative:
                        selected_index = idx
                        break
                
                param_to_change = random.randint(0, num_active - 1)
                k = random.choice([x for x in range(self.food_number) if x != selected_index]) if self.food_number > 1 else selected_index
                phi = random.uniform(-1, 1)
                candidate = foods[selected_index].copy()
                candidate[param_to_change] = max(0.0, min(1.0, candidate[param_to_change] + phi * (foods[selected_index][param_to_change] - foods[k][param_to_change])))
                
                candidate_fitness = calculate_fitness(candidate)
                if candidate_fitness > fitness[selected_index]:
                    foods[selected_index] = candidate
                    fitness[selected_index] = candidate_fitness
                    trial[selected_index] = 0
                else:
                    trial[selected_index] += 1

            # Best Update
            current_best_idx = fitness.index(max(fitness))
            if fitness[current_best_idx] > best_fitness:
                best_fitness = fitness[current_best_idx]
                best_food = foods[current_best_idx].copy()

            # Scout Bees
            max_trial_idx = trial.index(max(trial))
            if trial[max_trial_idx] > self.limit:
                foods[max_trial_idx] = [random.random() for _ in range(num_active)]
                fitness[max_trial_idx] = calculate_fitness(foods[max_trial_idx])
                trial[max_trial_idx] = 0

        best_allocations = decode(best_food)
        result = {}
        for cid, b_val in best_allocations.items():
            result[cid] = {
                "fill_rate": round(b_val, 2),
                "capacity": round(max(min_client_bandwidth, b_val * 2.0), 2)
            }
        result.update(blocked_allocations)
        return result
