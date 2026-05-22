from __future__ import annotations

from context_sast.helpers import java_name_from_descriptor
from context_sast.models import CorrelatedComponentContext, Finding

from .base import BaseDetector
from .common import finding_context_extras, manifest_prefixed_trace, sink_context_extras, sink_has_any_validation


class IntentRedirectionDetector(BaseDetector):
    detector_id = "intent_redirection"

    def detect(self, contexts: tuple[CorrelatedComponentContext, ...]) -> tuple[Finding, ...]:
        findings = []
        for context in contexts:
            component = context.component
            analysis = context.code_analysis
            if component.kind not in {"activity", "activity-alias", "service", "receiver"}:
                continue
            if not context.caller_exposure.zero_permission_reachable or analysis is None:
                continue
            if "caller_permission_check" in analysis.validations:
                continue

            sinks = [event for event in analysis.sink_events if event.kind in {"intent_redirection_sink", "intent_launch_sink"}]
            if not sinks:
                continue

            actionable = [
                sink
                for sink in sinks
                if any(provenance.tag in {"intent", "parcelable_extra", "serializable_extra"} for provenance in sink.provenances)
                if not sink_has_any_validation(sink, {"package_lock_validation", "component_lock_validation"})
            ]
            if not actionable:
                continue

            primary = actionable[0]
            confidence = "MEDIUM" if analysis.path_sensitive_validations else "HIGH"
            finding = Finding(
                title=f"Intent Redirection in {java_name_from_descriptor(component.name).split('.')[-1]}",
                severity="HIGH" if primary.kind == "intent_launch_sink" else "MEDIUM",
                confidence=confidence,
                owasp_category="M1: Improper Platform Usage",
                affected_component=java_name_from_descriptor(component.name),
                evidence=(
                    f"{java_name_from_descriptor(component.name)} is exported and routes external intent data into "
                    f"{primary.sink_signature.split('->', 1)[1].split('(', 1)[0]} without a strong access gate or validation."
                ),
                source_to_sink=manifest_prefixed_trace(context, primary),
                remediation=(
                    "Validate nested intents, component names, or destination packages before launching them, "
                    "or make the component unexported."
                ),
                detector=self.detector_id,
                extras={**finding_context_extras(context), **sink_context_extras(primary)},
            )
            findings.append(finding)
        return tuple(findings)
