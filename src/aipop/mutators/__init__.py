"""Mutator implementations."""

from aipop.mutators.encoding import EncodingMutator
from aipop.mutators.genetic import GeneticMutator
from aipop.mutators.html import HTMLMutator
from aipop.mutators.paraphrasing import ParaphrasingMutator
from aipop.mutators.unicode_mutator import UnicodeMutator

try:
    from aipop.mutators.gcg_mutator import GCGMutator

    __all__ = [
        "EncodingMutator",
        "GCGMutator",
        "GeneticMutator",
        "HTMLMutator",
        "ParaphrasingMutator",
        "UnicodeMutator",
    ]
except ImportError:
    __all__ = [
        "EncodingMutator",
        "GeneticMutator",
        "HTMLMutator",
        "ParaphrasingMutator",
        "UnicodeMutator",
    ]
