from __future__ import annotations

from context_sast.helpers import classify_permission_level, java_name_from_descriptor, protection_level_is_strong
from context_sast.models import CallerExposureContext, CodeComponentAnalysis, CorrelatedComponentContext, ManifestAnalysis


class Correlator:
    def correlate(
        self, manifest: ManifestAnalysis, code_analyses: dict[str, CodeComponentAnalysis]
    ) -> tuple[CorrelatedComponentContext, ...]:
        exposure_by_component = {
            component.name: self._build_exposure(component, manifest) for component in manifest.components
        }
        exposure_by_component = self._propagate_internal_reachability(manifest, code_analyses, exposure_by_component)
        contexts = []
        for component in manifest.components:
            contexts.append(
                CorrelatedComponentContext(
                    component=component,
                    code_analysis=code_analyses.get(component.name),
                    caller_exposure=exposure_by_component[component.name],
                )
            )
        return tuple(contexts)

    def _build_exposure(self, component, manifest: ManifestAnalysis) -> CallerExposureContext:
        effective_permission = component.permission or component.read_permission or component.write_permission
        permission_level = classify_permission_level(effective_permission, manifest.permissions)
        manifest_entry = self._manifest_entry(component, permission_level)

        if not component.exported and not component.grant_uri_permissions:
            return CallerExposureContext(False, "component is not externally reachable", effective_permission, permission_level, manifest_entry)

        permissions = [component.permission, component.read_permission, component.write_permission]
        strong_permissions = [perm for perm in permissions if protection_level_is_strong(perm, manifest.permissions)]
        if strong_permissions:
            return CallerExposureContext(
                False,
                f"protected by strong permission: {strong_permissions[0]}",
                effective_permission,
                permission_level,
                manifest_entry,
            )

        if any(permissions):
            return CallerExposureContext(
                False,
                "protected by a permission, but not classified as strong",
                effective_permission,
                permission_level,
                manifest_entry,
            )

        if component.grant_uri_permissions and component.kind == "provider":
            if component.exported:
                return CallerExposureContext(
                    True,
                    "provider is exported and also supports URI grants",
                    effective_permission,
                    permission_level,
                    manifest_entry,
                )
            return CallerExposureContext(
                False,
                "provider requires an explicit URI grant and is not exported",
                effective_permission,
                permission_level,
                manifest_entry,
            )

        if component.kind in {"activity", "activity-alias"} and self._is_browsable(component):
            return CallerExposureContext(
                True,
                "browsable exported activity without a strong permission gate",
                effective_permission,
                permission_level,
                manifest_entry,
            )

        return CallerExposureContext(
            True,
            "exported without a strong permission gate",
            effective_permission,
            permission_level,
            manifest_entry,
        )

    def _propagate_internal_reachability(
        self,
        manifest: ManifestAnalysis,
        code_analyses: dict[str, CodeComponentAnalysis],
        exposure_by_component: dict[str, CallerExposureContext],
    ) -> dict[str, CallerExposureContext]:
        known_components = {component.name for component in manifest.components}
        updated = dict(exposure_by_component)
        changed = True
        while changed:
            changed = False
            for component in manifest.components:
                source_exposure = updated[component.name]
                analysis = code_analyses.get(component.name)
                if not source_exposure.zero_permission_reachable or analysis is None:
                    continue
                for sink in analysis.sink_events:
                    target_component = sink.extra.get("target_component")
                    if sink.kind != "intent_launch_sink" or not target_component or target_component not in known_components:
                        continue
                    if not sink.provenances:
                        continue
                    target_exposure = updated[target_component]
                    ingress_trace = source_exposure.ingress_trace or (source_exposure.manifest_entry,)
                    ingress_trace = (*ingress_trace, *sink.provenances[0].trace)
                    ingress_validations = source_exposure.ingress_validations | sink.provenances[0].validations
                    ingress_source = source_exposure.ingress_source_component or java_name_from_descriptor(component.name)
                    reason = f"reachable via externally reachable component {java_name_from_descriptor(component.name)}"
                    candidate = CallerExposureContext(
                        True,
                        reason,
                        target_exposure.permission_name,
                        target_exposure.permission_level,
                        target_exposure.manifest_entry,
                        ingress_trace,
                        ingress_validations,
                        ingress_source,
                    )
                    if self._prefer(candidate, target_exposure):
                        updated[target_component] = candidate
                        changed = True
        return updated

    def _prefer(self, candidate: CallerExposureContext, current: CallerExposureContext) -> bool:
        if candidate.zero_permission_reachable and not current.zero_permission_reachable:
            return True
        if not candidate.zero_permission_reachable:
            return False
        if not current.ingress_trace:
            return False
        return bool(candidate.ingress_trace) and len(candidate.ingress_trace) < len(current.ingress_trace)

    def _manifest_entry(self, component, permission_level: str) -> str:
        filters = []
        for intent_filter in component.intent_filters:
            actions = ",".join(intent_filter.actions) if intent_filter.actions else "-"
            categories = ",".join(intent_filter.categories) if intent_filter.categories else "-"
            data = []
            for item in intent_filter.data:
                parts = [
                    part
                    for part in [
                        f"scheme={item.scheme}" if item.scheme else None,
                        f"host={item.host}" if item.host else None,
                        f"path={item.path}" if item.path else None,
                        f"pathPrefix={item.path_prefix}" if item.path_prefix else None,
                        f"pathPattern={item.path_pattern}" if item.path_pattern else None,
                        f"mime={item.mime_type}" if item.mime_type else None,
                    ]
                    if part
                ]
                if parts:
                    data.append(", ".join(parts))
            filters.append(f"actions=[{actions}] categories=[{categories}] data=[{'; '.join(data) if data else '-'}]")
        filter_text = "; ".join(filters) if filters else "none"
        permission_name = component.permission or component.read_permission or component.write_permission or "none"
        return (
            f"AndroidManifest.xml: <{component.kind} name=\"{java_name_from_descriptor(component.name)}\" exported={str(component.exported).lower()} "
            f"permission={permission_name} permission_level={permission_level} grantUriPermissions={str(component.grant_uri_permissions).lower()} "
            f"intent_filters={filter_text}>"
        )

    def _is_browsable(self, component) -> bool:
        for intent_filter in component.intent_filters:
            if "android.intent.category.BROWSABLE" in intent_filter.categories:
                return True
            if "android.intent.action.VIEW" in intent_filter.actions and intent_filter.data:
                return True
        return False
