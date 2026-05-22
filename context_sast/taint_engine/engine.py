from __future__ import annotations

from context_sast.helpers import cap_provenances, child_origin, method_trace_line
from context_sast.models import MethodRef, Provenance, SinkEvent


class TaintEngine:
    PASSTHROUGH_RETURN_TYPES = (
        "Ljava/lang/String;",
        "Landroid/net/Uri;",
        "Landroid/content/Intent;",
        "Landroid/os/Bundle;",
    )

    def _origin(self, method: MethodRef, tag: str, detail: str) -> str:
        return f"{method.signature}:{tag}:{detail}"

    def source_from_root(self, method: MethodRef, tag: str, detail: str) -> Provenance:
        """Create a fresh taint provenance for a source (entry param or mid-method call site)."""
        return Provenance(tag=tag, trace=(method_trace_line(method, detail),), origin=self._origin(method, tag, detail))

    def extend(self, provenance: Provenance, method: MethodRef, detail: str) -> Provenance:
        return Provenance(
            tag=provenance.tag,
            trace=provenance.trace + (method_trace_line(method, detail),),
            origin=provenance.origin,
            validations=provenance.validations,
        )

    def annotate_validation(self, provenance: Provenance, validation: str, method: MethodRef, detail: str) -> Provenance:
        return Provenance(
            tag=provenance.tag,
            trace=provenance.trace + (method_trace_line(method, detail),),
            origin=provenance.origin,
            validations=provenance.validations | {validation},
        )

    def derive(
        self,
        provenance: Provenance,
        tag: str,
        method: MethodRef,
        detail: str,
        preserve_origin: bool = True,
        carry_validations: bool = True,
    ) -> Provenance:
        return Provenance(
            tag=tag,
            trace=provenance.trace + (method_trace_line(method, detail),),
            origin=provenance.origin if preserve_origin else child_origin(provenance.origin, f"{tag}:{detail}"),
            validations=provenance.validations if carry_validations else frozenset(),
        )

    def build_sink_event(
        self,
        kind: str,
        method: MethodRef,
        sink_signature: str,
        provenances: tuple[Provenance, ...],
        detail: str,
        extra: dict[str, str] | None = None,
    ) -> SinkEvent:
        sink_line = method_trace_line(method, detail)
        final_provenances = tuple(self.extend(provenance, method, detail) for provenance in cap_provenances(provenances))
        return SinkEvent(
            kind=kind,
            method=method,
            sink_signature=sink_signature,
            provenances=final_provenances,
            evidence=sink_line,
            extra=extra or {},
        )

    def should_passthrough(self, target_signature: str) -> bool:
        return any(target_signature.endswith(return_type) for return_type in self.PASSTHROUGH_RETURN_TYPES)
