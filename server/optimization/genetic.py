import random
from .base import BaseOptimizer

class GeneticOptimizer(BaseOptimizer):
    """
    Genetik Algoritma (GA) tabanlı küresel bant genişliği dağıtıcısı.
    """
    def __init__(self, pop_size=50, generations=80, mutation_rate=0.15):
        self.pop_size = pop_size
        self.generations = generations
        self.mutation_rate = mutation_rate

    def allocate(self, clients: list, global_max_bandwidth: float, min_client_bandwidth: float) -> dict:
        if not clients:
            return {}

        # 1. Aşama: Tamamen bloke olması gereken (Risk >= 90) cihazları ayır.
        # Bu cihazlara 0 bant genişliği atanır ve havuza dahil edilmezler.
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
            # Tüm cihazlar bloke olmuşsa veya aktif cihaz yoksa
            return blocked_allocations

        num_active = len(active_clients)
        
        # Toplam havuzdan, her aktif cihaz için asgari bant genişliğini rezerve et
        reserved_bandwidth = num_active * min_client_bandwidth
        remaining_pool = max(0.0, global_max_bandwidth - reserved_bandwidth)

        # Genetik Temsil: Kromozom = [w_1, w_2, ..., w_N] (Her aktif istemci için 0.0 - 1.0 arası ağırlık payı)
        # B_i = min_client_bandwidth + remaining_pool * (w_i / toplam_w)

        def decode(chromosome):
            """Kromozomu gerçek hız değerlerine (Byte/sn) dönüştürür."""
            sum_w = sum(chromosome)
            allocations = {}
            if sum_w == 0:
                # Eşit paylaşım fallback
                share = remaining_pool / num_active
                for idx, c in enumerate(active_clients):
                    allocations[c["id"]] = min_client_bandwidth + share
            else:
                for idx, c in enumerate(active_clients):
                    weight = chromosome[idx] / sum_w
                    allocations[c["id"]] = min_client_bandwidth + (remaining_pool * weight)
            return allocations

        def calculate_fitness(chromosome):
            """Kromozomun uygunluk (Fitness) değerini hesaplar."""
            allocations = decode(chromosome)
            score_sum = 0.0
            for c in active_clients:
                b_i = allocations[c["id"]]
                priority = float(c["priority"])
                risk_score = float(c["risk_score"])
                
                # Risk arttıkça cihazın log gönderme yararı (utility) düşer
                utility_factor = 1.0 - (risk_score / 100.0)
                score_sum += b_i * priority * utility_factor
            return score_sum

        # 2. Aşama: İlk Popülasyonu Oluştur
        population = []
        for _ in range(self.pop_size):
            chromosome = [random.random() for _ in range(num_active)]
            population.append(chromosome)

        # 3. Aşama: Genetik Döngü (Generations)
        for gen in range(self.generations):
            # Fitness değerlerini hesapla
            fitness_scores = [calculate_fitness(chrom) for chrom in population]
            
            # Yeni nesil havuzu
            new_population = []

            # Seçilim (Tournament Selection)
            def select_parent():
                tournament = random.sample(list(zip(population, fitness_scores)), 3)
                # En yüksek fitness'a sahip olanı seç
                tournament.sort(key=lambda x: x[1], reverse=True)
                return tournament[0][0]

            # Elitizm: En iyi 2 kromozomu doğrudan bir sonraki nesle aktar
            best_idx = fitness_scores.index(max(fitness_scores))
            new_population.append(population[best_idx])
            
            # Popülasyonu tamamla
            while len(new_population) < self.pop_size:
                parent1 = select_parent()
                parent2 = select_parent()

                # Crossover (Tek Noktalı Çaprazlama)
                if random.random() < 0.8:
                    cross_point = random.randint(1, num_active - 1) if num_active > 1 else 0
                    child1 = parent1[:cross_point] + parent2[cross_point:]
                    child2 = parent2[:cross_point] + parent1[cross_point:]
                else:
                    child1, child2 = parent1.copy(), parent2.copy()

                # Mutasyon
                for child in [child1, child2]:
                    for i in range(num_active):
                        if random.random() < self.mutation_rate:
                            # Ağırlığı hafifçe değiştir (+/- 0.2)
                            child[i] = max(0.0, min(1.0, child[i] + random.uniform(-0.2, 0.2)))
                    if len(new_population) < self.pop_size:
                        new_population.append(child)

            population = new_population

        # 4. Aşama: En İyi Sonucu Seç ve Çıktıyı Formatla
        final_fitness = [calculate_fitness(chrom) for chrom in population]
        best_chrom = population[final_fitness.index(max(final_fitness))]
        best_allocations = decode(best_chrom)

        # Bloklanan ve aktif cihazların sonuçlarını birleştir
        result = {}
        for cid, b_val in best_allocations.items():
            result[cid] = {
                "fill_rate": round(b_val, 2),
                # Kapasite olarak saniyelik gönderme sınırının 2 katını ayarla (Burst tolere etmek için)
                "capacity": round(max(min_client_bandwidth, b_val * 2.0), 2)
            }
        
        # Engellenenleri ekle
        result.update(blocked_allocations)
        return result
