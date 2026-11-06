from .base import BaseOptimizer
from .genetic import GeneticOptimizer
from .proportional_fair import ProportionalFairOptimizer
from .abc import ABCOptimizer
from .pso import PSOOptimizer
from .simulated_annealing import SimulatedAnnealingOptimizer
from .max_min_fair import MaxMinFairOptimizer

def get_optimizer(name: str) -> BaseOptimizer:
    """
    Seçilen isme göre uygun optimizasyon nesnesini döner.
    """
    name_lower = name.lower().strip()
    if "genetic" in name_lower or "genetik" in name_lower:
        return GeneticOptimizer()
    elif "pso" in name_lower or "swarm" in name_lower or "suru" in name_lower:
        return PSOOptimizer()
    elif "abc" in name_lower or "bee" in name_lower or "ari" in name_lower:
        return ABCOptimizer()
    elif "anneal" in name_lower or "tavla" in name_lower:
        return SimulatedAnnealingOptimizer()
    elif "max_min" in name_lower or "mmf" in name_lower:
        return MaxMinFairOptimizer()
    elif "proportional" in name_lower or "fair" in name_lower or "adil" in name_lower:
        return ProportionalFairOptimizer()
    else:
        # Varsayılan yedek plan
        return ProportionalFairOptimizer()
