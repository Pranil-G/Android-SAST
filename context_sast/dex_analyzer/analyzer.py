from __future__ import annotations

import sys
from collections import defaultdict

from loguru import logger

from androguard.misc import AnalyzeAPK

from context_sast.helpers import is_framework_class
from context_sast.models import DexAnalysisResult, MethodRef


class DexAnalyzer:
    _logging_configured: bool = False

    def analyze(self, apk_path: str) -> DexAnalysisResult:
        self._configure_logging()
        apk, dalvik_vms, analysis = AnalyzeAPK(apk_path)

        methods: dict[str, object] = {}
        methods_by_class: dict[str, list[MethodRef]] = defaultdict(list)
        app_class_descriptors: set[str] = set()

        for method_analysis in analysis.get_methods():
            method = method_analysis.get_method()
            if not hasattr(method, "get_code") or method.get_code() is None:
                continue

            ref = MethodRef(
                class_name=method.get_class_name(),
                name=method.get_name(),
                descriptor=method.get_descriptor(),
            )
            methods[ref.signature] = method_analysis
            methods_by_class[ref.class_name].append(ref)
            if not is_framework_class(ref.class_name):
                app_class_descriptors.add(ref.class_name)

        return DexAnalysisResult(
            apk=apk,
            dalvik_vms=tuple(dalvik_vms),
            analysis=analysis,
            methods=methods,
            methods_by_class={key: tuple(value) for key, value in methods_by_class.items()},
            app_class_descriptors=frozenset(app_class_descriptors),
        )

    def _configure_logging(self) -> None:
        if DexAnalyzer._logging_configured:
            return
        logger.remove()
        logger.add(sys.stderr, level="ERROR")
        DexAnalyzer._logging_configured = True
