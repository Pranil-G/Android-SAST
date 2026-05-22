from __future__ import annotations

from context_sast.helpers import java_name_from_descriptor
from context_sast.models import CorrelatedComponentContext, Finding

from .base import BaseDetector
from .common import finding_context_extras, manifest_prefixed_trace, sink_context_extras, sink_or_ingress_has_any_validation


class WebViewMisconfigurationDetector(BaseDetector):
    detector_id = "webview_misconfiguration"

    def detect(self, contexts: tuple[CorrelatedComponentContext, ...]) -> tuple[Finding, ...]:
        findings = []
        for context in contexts:
            analysis = context.code_analysis
            if analysis is None:
                continue
            if not context.caller_exposure.zero_permission_reachable:
                continue

            sinks = [event for event in analysis.sink_events if event.kind == "webview_load_sink"]
            if not sinks or "webview_js_enabled" not in analysis.flags:
                continue

            actionable = [sink for sink in sinks if not sink_or_ingress_has_any_validation(context, sink, {"url_allowlist_validation"})]
            if not actionable:
                continue

            all_validations = set(analysis.path_sensitive_validations) | set(context.caller_exposure.ingress_validations)
            confidence = "MEDIUM" if all_validations else "HIGH"
            modifiers = []
            if "webview_allow_file_access" in analysis.flags:
                modifiers.append("file access enabled")
            if "webview_file_url_access" in analysis.flags:
                modifiers.append("file URL access enabled")
            if "webview_universal_file_access" in analysis.flags:
                modifiers.append("universal file URL access enabled")
            if "webview_js_interface" in analysis.flags:
                modifiers.append("JavaScript interface exposed")

            severity = "HIGH" if modifiers else "MEDIUM"
            extra = f" Risk modifiers: {', '.join(modifiers)}." if modifiers else ""
            primary = actionable[0]
            flawed_check = "flawed_url_validation" in context.caller_exposure.ingress_validations or any(
                "flawed_url_validation" in provenance.validations for provenance in primary.provenances
            )
            flawed_text = " A URL check exists but appears bypassable." if flawed_check else ""
            findings.append(
                Finding(
                    title=f"WebView Misconfiguration in {java_name_from_descriptor(context.component.name).split('.')[-1]}",
                    severity=severity,
                    confidence=confidence,
                    owasp_category="M3: Insecure Communication",
                    affected_component=java_name_from_descriptor(context.component.name),
                    evidence=(
                        f"External input reaches WebView content loading while JavaScript is enabled.{flawed_text}{extra}"
                    ),
                    source_to_sink=manifest_prefixed_trace(context, primary),
                    remediation=(
                        "Validate and allowlist URLs with exact scheme/host rules before loading them, keep JavaScript disabled by default, "
                        "and avoid dangerous WebView file access settings."
                    ),
                    detector=self.detector_id,
                    extras={**finding_context_extras(context), **sink_context_extras(primary)},
                )
            )
        return tuple(findings)
