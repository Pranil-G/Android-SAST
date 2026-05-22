from __future__ import annotations

from abc import ABC, abstractmethod

from context_sast.models import CorrelatedComponentContext, Finding


class BaseDetector(ABC):
    detector_id: str

    @abstractmethod
    def detect(self, contexts: tuple[CorrelatedComponentContext, ...]) -> tuple[Finding, ...]:
        ...
