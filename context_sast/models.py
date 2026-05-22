from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class LoadedApk:
    path: Path
    sha256: str
    size_bytes: int


@dataclass(frozen=True)
class ManifestPermission:
    name: str
    protection_level: str | None = None


@dataclass(frozen=True)
class IntentFilterData:
    scheme: str | None = None
    host: str | None = None
    path: str | None = None
    path_prefix: str | None = None
    path_pattern: str | None = None
    mime_type: str | None = None


@dataclass(frozen=True)
class IntentFilterInfo:
    actions: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()
    data: tuple[IntentFilterData, ...] = ()


@dataclass(frozen=True)
class ComponentInfo:
    name: str
    kind: str
    exported: bool
    implicitly_exported: bool
    permission: str | None = None
    read_permission: str | None = None
    write_permission: str | None = None
    grant_uri_permissions: bool = False
    authorities: tuple[str, ...] = ()
    intent_filters: tuple[IntentFilterInfo, ...] = ()


@dataclass(frozen=True)
class ManifestAnalysis:
    package_name: str
    min_sdk: int | None
    target_sdk: int | None
    permissions: dict[str, ManifestPermission]
    components: tuple[ComponentInfo, ...]


@dataclass(frozen=True)
class MethodRef:
    class_name: str
    name: str
    descriptor: str

    @property
    def signature(self) -> str:
        return f"{self.class_name}->{self.name}{self.descriptor}"


@dataclass(frozen=True)
class Provenance:
    tag: str
    trace: tuple[str, ...]
    origin: str = ""
    validations: frozenset[str] = frozenset()


@dataclass(frozen=True)
class SinkEvent:
    kind: str
    method: MethodRef
    sink_signature: str
    provenances: tuple[Provenance, ...]
    evidence: str
    extra: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class MethodFlowSummary:
    return_provenances: tuple[Provenance, ...] = ()
    sink_events: tuple[SinkEvent, ...] = ()
    flags: frozenset[str] = frozenset()
    validations: frozenset[str] = frozenset()


@dataclass
class DexAnalysisResult:
    apk: Any
    dalvik_vms: tuple[Any, ...]
    analysis: Any
    methods: dict[str, Any]
    methods_by_class: dict[str, tuple[MethodRef, ...]]
    app_class_descriptors: frozenset[str]


@dataclass(frozen=True)
class CodeComponentAnalysis:
    component: ComponentInfo
    entry_methods: tuple[MethodRef, ...]
    sink_events: tuple[SinkEvent, ...]
    flags: frozenset[str]
    validations: frozenset[str]
    path_sensitive_validations: frozenset[str]
    visited_methods: tuple[str, ...]


@dataclass(frozen=True)
class CallerExposureContext:
    zero_permission_reachable: bool
    protection_reason: str
    permission_name: str | None = None
    permission_level: str = "none"
    manifest_entry: str = ""
    ingress_trace: tuple[str, ...] = ()
    ingress_validations: frozenset[str] = frozenset()
    ingress_source_component: str | None = None


@dataclass(frozen=True)
class CorrelatedComponentContext:
    component: ComponentInfo
    code_analysis: CodeComponentAnalysis | None
    caller_exposure: CallerExposureContext


@dataclass(frozen=True)
class Finding:
    title: str
    severity: str
    confidence: str
    owasp_category: str
    affected_component: str
    evidence: str
    source_to_sink: tuple[str, ...]
    remediation: str
    detector: str
    extras: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ScanResult:
    apk_path: str
    package_name: str
    findings: tuple[Finding, ...]
