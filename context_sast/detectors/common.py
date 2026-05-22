from __future__ import annotations

from context_sast.helpers import java_name_from_descriptor
from context_sast.models import CorrelatedComponentContext, SinkEvent


def sink_has_validation(sink: SinkEvent, validation: str) -> bool:
    return any(validation in provenance.validations for provenance in sink.provenances)


def sink_has_any_validation(sink: SinkEvent, validations: set[str]) -> bool:
    return any(
        not validations.isdisjoint(provenance.validations)
        for provenance in sink.provenances
    )


def sink_has_tag(sink: SinkEvent, tags: set[str]) -> bool:
    return any(provenance.tag in tags for provenance in sink.provenances)


def sink_or_ingress_has_any_validation(
    context: CorrelatedComponentContext, sink: SinkEvent, validations: set[str]
) -> bool:
    if sink_has_any_validation(sink, validations):
        return True
    return any(validation in context.caller_exposure.ingress_validations for validation in validations)


def finding_context_extras(context: CorrelatedComponentContext) -> dict[str, str]:
    extras = {
        "component_exported": str(context.component.exported).lower(),
        "component_permission": context.caller_exposure.permission_name or "none",
        "component_permission_level": context.caller_exposure.permission_level,
        "exposure_reason": context.caller_exposure.protection_reason,
        "manifest_entry": context.caller_exposure.manifest_entry,
        "browsable_filter_precision": browsable_filter_precision(context.component),
        "browsable_filter_constraints": browsable_filter_constraints(context.component),
    }
    if context.caller_exposure.ingress_source_component:
        extras["ingress_source_component"] = context.caller_exposure.ingress_source_component
    if context.caller_exposure.ingress_trace:
        extras["ingress_trace"] = " | ".join(context.caller_exposure.ingress_trace)
    return extras


def manifest_prefixed_trace(context: CorrelatedComponentContext, sink: SinkEvent) -> tuple[str, ...]:
    sink_trace = sink.provenances[0].trace if sink.provenances else ()
    if context.caller_exposure.ingress_trace:
        return (*context.caller_exposure.ingress_trace, context.caller_exposure.manifest_entry, *sink_trace)
    return (context.caller_exposure.manifest_entry, *sink_trace)


def sink_context_extras(sink: SinkEvent) -> dict[str, str]:
    extras: dict[str, str] = {}
    if sink.extra.get("target_component"):
        extras["sink_target_component"] = java_name_from_descriptor(sink.extra["target_component"])
    if sink.extra.get("intent_action"):
        extras["sink_intent_action"] = sink.extra["intent_action"]
    if sink.extra.get("launch_control"):
        extras["launch_control"] = sink.extra["launch_control"]
    extras["sink_signature"] = sink.sink_signature
    extras["sink_kind"] = sink.kind
    return extras


def browsable_filter_precision(component) -> str:
    browsable_filters = [
        intent_filter
        for intent_filter in component.intent_filters
        if "android.intent.category.BROWSABLE" in intent_filter.categories
        or ("android.intent.action.VIEW" in intent_filter.actions and intent_filter.data)
    ]
    if not browsable_filters:
        return "none"
    precise = True
    has_exact_path = False
    for intent_filter in browsable_filters:
        if not intent_filter.data:
            return "broad"
        for item in intent_filter.data:
            if not item.scheme or not item.host:
                precise = False
            if item.path:
                has_exact_path = True
            if item.path_prefix or item.path_pattern:
                precise = False
    if precise and has_exact_path:
        return "exact_path"
    if precise:
        return "exact_host"
    return "broad"


def browsable_filter_constraints(component) -> str:
    constraints: list[str] = []
    for intent_filter in component.intent_filters:
        if "android.intent.category.BROWSABLE" not in intent_filter.categories and (
            "android.intent.action.VIEW" not in intent_filter.actions or not intent_filter.data
        ):
            continue
        for item in intent_filter.data:
            parts = []
            if item.scheme:
                parts.append(f"scheme={item.scheme}")
            if item.host:
                parts.append(f"host={item.host}")
            if item.path:
                parts.append(f"path={item.path}")
            if item.path_prefix:
                parts.append(f"pathPrefix={item.path_prefix}")
            if item.path_pattern:
                parts.append(f"pathPattern={item.path_pattern}")
            if parts:
                constraints.append(", ".join(parts))
    return " | ".join(constraints) if constraints else "none"
