from __future__ import annotations

from context_sast.apk_loader import ApkLoader
from context_sast.correlator import Correlator
from context_sast.dataflow_engine import DataflowEngine
from context_sast.dex_analyzer import DexAnalyzer
from context_sast.manifest_analyzer import ManifestAnalyzer
from context_sast.models import ScanResult
from context_sast.rule_engine import RuleEngine


class ContextAwareSASTEngine:
    def __init__(self, max_depth: int = 4) -> None:
        self.apk_loader = ApkLoader()
        self.dex_analyzer = DexAnalyzer()
        self.manifest_analyzer = ManifestAnalyzer()
        self.dataflow_engine = DataflowEngine(max_depth=max_depth)
        self.correlator = Correlator()
        self.rule_engine = RuleEngine()

    def scan(self, apk_path: str) -> ScanResult:
        loaded = self.apk_loader.load(apk_path)
        dex_result = self.dex_analyzer.analyze(str(loaded.path))
        manifest_result = self.manifest_analyzer.analyze(dex_result.apk)
        code_analyses = self.dataflow_engine.analyze_components(manifest_result, dex_result)
        contexts = self.correlator.correlate(manifest_result, code_analyses)
        findings = self.rule_engine.run(contexts)

        return ScanResult(
            apk_path=str(loaded.path),
            package_name=manifest_result.package_name,
            findings=findings,
        )
