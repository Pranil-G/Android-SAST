from __future__ import annotations

from context_sast.helpers import java_name_from_descriptor
from context_sast.models import CorrelatedComponentContext, Finding

from .base import BaseDetector
from .common import finding_context_extras, manifest_prefixed_trace, sink_context_extras, sink_has_any_validation


class InsecureContentProviderDetector(BaseDetector):
    detector_id = "insecure_content_provider"

    def detect(self, contexts: tuple[CorrelatedComponentContext, ...]) -> tuple[Finding, ...]:
        findings = []
        for context in contexts:
            component = context.component
            analysis = context.code_analysis
            if component.kind != "provider" or analysis is None:
                continue
            if not context.caller_exposure.zero_permission_reachable:
                continue
            if component.name == "Landroidx/core/content/FileProvider;":
                continue
            if component.read_permission or component.write_permission or component.permission:
                continue
            if "caller_permission_check" in analysis.validations:
                continue

            path_sinks = [
                event
                for event in analysis.sink_events
                if event.kind == "provider_path_file_sink" and not sink_has_any_validation(event, {"canonical_path_validation"})
            ]
            has_file_exposure = bool(
                [entry for entry in analysis.entry_methods if entry.name in {"openFile", "openAssetFile", "query"}]
            )
            if not path_sinks and not has_file_exposure:
                continue

            severity = "HIGH" if path_sinks else "MEDIUM"
            confidence = "HIGH" if path_sinks else "MEDIUM"
            evidence = (
                "Provider is externally reachable without read/write protection and builds file paths from caller-controlled URI data."
                if path_sinks
                else "Provider is externally reachable without read/write protection and exposes file-style entrypoints without observed caller checks."
            )
            source_to_sink = path_sinks[0].provenances[0].trace if path_sinks and path_sinks[0].provenances else ()
            extras = finding_context_extras(context)
            if path_sinks:
                extras.update(sink_context_extras(path_sinks[0]))
            findings.append(
                Finding(
                    title=f"Insecure ContentProvider in {java_name_from_descriptor(component.name).split('.')[-1]}",
                    severity=severity,
                    confidence=confidence,
                    owasp_category="M2: Insecure Data Storage",
                    affected_component=java_name_from_descriptor(component.name),
                    evidence=evidence,
                    source_to_sink=(context.caller_exposure.manifest_entry, *source_to_sink) if source_to_sink else (context.caller_exposure.manifest_entry,),
                    remediation=(
                        "Require explicit read/write permissions or caller checks, and canonicalize filesystem paths "
                        "derived from URI segments before using them."
                    ),
                    detector=self.detector_id,
                    extras=extras,
                )
            )
        return tuple(findings)
