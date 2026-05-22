from __future__ import annotations

import re
import sys
import traceback
from collections import defaultdict
from dataclasses import dataclass

from context_sast.helpers import REGISTER_RE, cap_provenances, parse_const_class, parse_invoke_output
from context_sast.models import CodeComponentAnalysis, ComponentInfo, DexAnalysisResult, ManifestAnalysis, MethodFlowSummary, MethodRef, Provenance
from context_sast.taint_engine import TaintEngine

CONST_STR_RE = re.compile(r"^(v\d+),\s*\"(.*)\"$")
CONST_NUM_RE = re.compile(r"^(v\d+),\s*(-?0x[0-9a-fA-F]+|-?\d+)$")
SINGLE_REGISTER_RE = re.compile(r"^(v\d+)$")
INSTANCE_FIELD_RE = re.compile(r"^(v\d+),\s*(v\d+),\s*(L[^;]+;->[^\s]+)$")
STATIC_FIELD_RE = re.compile(r"^(v\d+),\s*(L[^;]+;->[^\s]+)$")

BOOLEAN_VALIDATION_CALLS = {
    "startsWith",
    "endsWith",
    "matches",
    "contains",
    "equals",
    "equalsIgnoreCase",
}

BRANCH_TARGET_RE = re.compile(r"([+-][0-9a-fA-F]+h?)$")


@dataclass(frozen=True)
class GuardScope:
    end_offset: int
    source_provenances: tuple[Provenance, ...]
    origins: frozenset[str]
    validation: str
    detail: str


class DataflowEngine:
    def __init__(self, max_depth: int = 4) -> None:
        self.max_depth = max_depth
        self.taint_engine = TaintEngine()
        self.dex: DexAnalysisResult | None = None
        self._cache: dict[tuple[str, tuple[tuple[Provenance, ...], ...]], MethodFlowSummary] = {}
        self._stack: set[tuple[str, tuple[tuple[Provenance, ...], ...]]] = set()

    def analyze_components(
        self, manifest: ManifestAnalysis, dex: DexAnalysisResult
    ) -> dict[str, CodeComponentAnalysis]:
        self.dex = dex
        self._cache.clear()
        self._stack.clear()

        analyses: dict[str, CodeComponentAnalysis] = {}
        for component in manifest.components:
            entry_methods = self._resolve_entry_methods(component, dex)
            if not entry_methods:
                continue

            sink_events = []
            flags = set()
            validations = set()
            path_sensitive_validations = set()
            visited_methods = set()

            for entry_method, arg_taints in entry_methods:
                try:
                    summary = self._analyze_method(entry_method, arg_taints, 0)
                except Exception as exc:  # noqa: BLE001
                    print(
                        f"[dataflow] ERROR analyzing {entry_method.signature}: {exc}",
                        file=sys.stderr,
                    )
                    traceback.print_exc(file=sys.stderr)
                    summary = MethodFlowSummary()
                sink_events.extend(summary.sink_events)
                flags.update(summary.flags)
                validations.update(summary.validations)
                path_sensitive_validations.update(self._collect_path_sensitive_validations(summary))
                visited_methods.add(entry_method.signature)

            analyses[component.name] = CodeComponentAnalysis(
                component=component,
                entry_methods=tuple(entry for entry, _ in entry_methods),
                sink_events=tuple(sink_events),
                flags=frozenset(flags),
                validations=frozenset(validations),
                path_sensitive_validations=frozenset(path_sensitive_validations),
                visited_methods=tuple(sorted(visited_methods)),
            )

        return analyses

    def _resolve_entry_methods(
        self, component: ComponentInfo, dex: DexAnalysisResult
    ) -> list[tuple[MethodRef, tuple[tuple[Provenance, ...], ...]]]:
        method_names = {
            "activity": ("onCreate", "onNewIntent", "onStart", "onResume"),
            "activity-alias": ("onCreate", "onNewIntent", "onStart", "onResume"),
            "service": ("onStartCommand", "onBind", "onHandleIntent"),
            "receiver": ("onReceive",),
            "provider": ("query", "openFile", "openAssetFile", "insert", "update", "delete", "getType"),
        }.get(component.kind, ())
        class_methods = self.dex.methods_by_class.get(component.name, ()) if self.dex else ()
        selected = [method for method in class_methods if method.name in method_names]
        entry_points: list[tuple[MethodRef, tuple[tuple[Provenance, ...], ...]]] = []

        for method in selected:
            param_count = len(self._param_registers(method))
            args = [tuple() for _ in range(param_count)]
            if component.kind == "receiver" and method.name == "onReceive" and param_count >= 2:
                args[1] = (self.taint_engine.source_from_root(method, "intent", "external intent parameter"),)
            elif component.kind == "service" and method.name in {"onStartCommand", "onBind", "onHandleIntent"} and param_count >= 1:
                args[0] = (self.taint_engine.source_from_root(method, "intent", "external intent parameter"),)
            elif component.kind in {"activity", "activity-alias"} and method.name == "onNewIntent" and param_count >= 1:
                args[0] = (self.taint_engine.source_from_root(method, "intent", "external intent parameter"),)
            elif component.kind == "provider" and param_count >= 1:
                args[0] = (self.taint_engine.source_from_root(method, "provider_uri", "external URI parameter"),)
            entry_points.append((method, tuple(args)))
        return entry_points

    def _analyze_method(
        self, method_ref: MethodRef, incoming_args: tuple[tuple[Provenance, ...], ...], depth: int
    ) -> MethodFlowSummary:
        cache_key = (method_ref.signature, incoming_args)
        if cache_key in self._cache:
            return self._cache[cache_key]
        if cache_key in self._stack or depth > self.max_depth or self.dex is None:
            return MethodFlowSummary()

        method_analysis = self.dex.methods.get(method_ref.signature)
        if method_analysis is None:
            return MethodFlowSummary()

        self._stack.add(cache_key)
        method = method_analysis.get_method()
        reg_taints: dict[str, tuple[Provenance, ...]] = defaultdict(tuple)
        reg_consts: dict[str, int | str] = {}
        reg_classes: dict[str, str] = {}
        field_taints: dict[str, tuple[Provenance, ...]] = {}
        array_taints: dict[str, tuple[Provenance, ...]] = {}
        intent_targets: dict[str, str] = {}
        intent_actions: dict[str, str] = {}
        intent_payload_taints: dict[str, tuple[Provenance, ...]] = {}
        last_result: tuple[Provenance, ...] = ()
        last_validation_result: tuple[str, tuple[Provenance, ...], str] | None = None
        last_intent_alias_source: str | None = None
        validation_registers: dict[str, tuple[str, tuple[Provenance, ...], str]] = {}
        active_guards: list[GuardScope] = []
        sink_events = []
        flags = set()
        validations = set()

        for register, taints in zip(self._param_registers(method_ref), incoming_args, strict=False):
            reg_taints[register] = cap_provenances(taints)

        for offset, instruction in method.get_instructions_idx():
            active_guards = [guard for guard in active_guards if offset < guard.end_offset]
            name = instruction.get_name()
            output = instruction.get_output()
            # Reset per-instruction carry state; keep it only for move-result.
            if not name.startswith("move-result"):
                last_result = ()
                last_validation_result = None
                last_intent_alias_source = None

            if name.startswith("const-string"):
                parsed = self._parse_const_string(output)
                if parsed:
                    reg, value = parsed
                    reg_consts[reg] = value
                    reg_classes.pop(reg, None)
                    reg_taints.pop(reg, None)
                continue

            if name.startswith("const-class"):
                parsed = parse_const_class(output)
                if parsed:
                    reg, value = parsed
                    reg_classes[reg] = value
                    reg_taints.pop(reg, None)
                continue

            if name.startswith("const"):
                parsed = self._parse_const_number(output)
                if parsed:
                    reg, value = parsed
                    reg_consts[reg] = value
                    reg_classes.pop(reg, None)
                    reg_taints.pop(reg, None)
                continue

            if name.startswith("move-result"):
                dest = self._parse_single_register(output)
                if dest:
                    reg_taints[dest] = last_result
                    if last_validation_result:
                        validation_registers[dest] = last_validation_result
                    else:
                        validation_registers.pop(dest, None)
                    if last_intent_alias_source:
                        if last_intent_alias_source in intent_targets:
                            intent_targets[dest] = intent_targets[last_intent_alias_source]
                        if last_intent_alias_source in intent_actions:
                            intent_actions[dest] = intent_actions[last_intent_alias_source]
                        if last_intent_alias_source in intent_payload_taints:
                            intent_payload_taints[dest] = intent_payload_taints[last_intent_alias_source]
                # carry state already reset at the top of the loop
                continue

            if name.startswith("move"):
                regs = REGISTER_RE.findall(output)
                if len(regs) >= 2:
                    reg_taints[regs[0]] = reg_taints.get(regs[1], ())
                    if regs[1] in reg_consts:
                        reg_consts[regs[0]] = reg_consts[regs[1]]
                    if regs[1] in reg_classes:
                        reg_classes[regs[0]] = reg_classes[regs[1]]
                    if regs[1] in array_taints:
                        array_taints[regs[0]] = array_taints[regs[1]]
                    if regs[1] in intent_targets:
                        intent_targets[regs[0]] = intent_targets[regs[1]]
                    if regs[1] in intent_actions:
                        intent_actions[regs[0]] = intent_actions[regs[1]]
                    if regs[1] in intent_payload_taints:
                        intent_payload_taints[regs[0]] = intent_payload_taints[regs[1]]
                continue

            if name.startswith("if-"):
                regs = REGISTER_RE.findall(output)
                if regs:
                    guard = self._branch_guard(
                        method_ref=method_ref,
                        opcode=name,
                        output=output,
                        offset=offset,
                        registers=regs,
                        validation_registers=validation_registers,
                    )
                    if guard:
                        active_guards.append(guard)
                        validations.add(guard.validation)
                continue

            if name.startswith("aget"):
                regs = REGISTER_RE.findall(output)
                if len(regs) >= 2:
                    reg_taints[regs[0]] = array_taints.get(regs[1], ())
                continue

            if name.startswith("aput"):
                regs = REGISTER_RE.findall(output)
                if len(regs) >= 2:
                    array_taints[regs[1]] = cap_provenances(
                        provenance for provenance in (*array_taints.get(regs[1], ()), *reg_taints.get(regs[0], ()))
                    )
                continue

            if name.startswith("iget") or name.startswith("iput"):
                parsed_field = self._parse_instance_field(output)
                if parsed_field:
                    first_reg, _, field_sig = parsed_field
                    if name.startswith("iget"):
                        reg_taints[first_reg] = field_taints.get(field_sig, ())
                    else:
                        field_taints[field_sig] = reg_taints.get(first_reg, ())
                continue

            if name.startswith("sget") or name.startswith("sput"):
                parsed_static_field = self._parse_static_field(output)
                if parsed_static_field:
                    reg, field_sig = parsed_static_field
                    if name.startswith("sget"):
                        reg_taints[reg] = field_taints.get(field_sig, ())
                    else:
                        field_taints[field_sig] = reg_taints.get(reg, ())
                continue

            if name.startswith("return"):
                ret_reg = self._parse_single_register(output)
                summary = MethodFlowSummary(
                    return_provenances=cap_provenances(reg_taints.get(ret_reg, ()) if ret_reg else ()),
                    sink_events=tuple(sink_events),
                    flags=frozenset(flags),
                    validations=frozenset(validations),
                )
                self._cache[cache_key] = summary
                self._stack.remove(cache_key)
                return summary

            # check-cast is a type-narrowing opcode that modifies a register
            # in-place (no move-result follows it in Dalvik). Preserve whatever
            # taint the register already carries.
            if name == "check-cast":
                # reg_taints for the cast register is unchanged; nothing to do.
                continue

            if not name.startswith("invoke-"):
                continue

            parsed_invoke = parse_invoke_output(output)
            if not parsed_invoke:
                continue

            registers, target = parsed_invoke
            arg_taints = tuple(self._apply_active_guards(method_ref, reg_taints.get(reg, ()), active_guards) for reg in registers)
            const_args = tuple(reg_consts.get(reg) for reg in registers)
            target_name = _target_name(target)

            last_intent_alias_source = self._update_intent_state(
                method_ref=method_ref,
                target=target,
                target_name=target_name,
                registers=registers,
                arg_taints=arg_taints,
                reg_taints=reg_taints,
                reg_classes=reg_classes,
                reg_consts=reg_consts,
                intent_targets=intent_targets,
                intent_actions=intent_actions,
                intent_payload_taints=intent_payload_taints,
            )

            source_result = self._source_for_call(method_ref, target, arg_taints, const_args)
            last_result = source_result or ()
            last_validation_result = self._pending_validation_for_call(method_ref, target_name, arg_taints, const_args)

            sink_event = self._sink_for_call(
                method_ref=method_ref,
                target=target,
                target_name=target_name,
                registers=registers,
                arg_taints=arg_taints,
                intent_targets=intent_targets,
                intent_actions=intent_actions,
                intent_payload_taints=intent_payload_taints,
                active_guards=active_guards,
            )
            if sink_event:
                sink_events.append(sink_event)

            new_flag = self._flag_for_call(target, const_args)
            if new_flag:
                flags.add(new_flag)

            immediate_validations = self._immediate_validations_for_call(method_ref, target_name, registers, arg_taints)
            for validation, affected_registers in immediate_validations:
                self._annotate_registers(method_ref, reg_taints, affected_registers, validation, validations)

            if target_name in {"checkCallingPermission", "checkCallingOrSelfPermission", "enforceCallingPermission", "enforceCallingOrSelfPermission"}:
                validations.add("caller_permission_check")

            if target in self.dex.methods:
                callee_args = arg_taints if name.endswith("static") else arg_taints[1:]
                callee_method = self.dex.methods[target].get_method()
                callee_ref = MethodRef(
                    class_name=callee_method.get_class_name(),
                    name=callee_method.get_name(),
                    descriptor=callee_method.get_descriptor(),
                )
                callee_summary = self._analyze_method(callee_ref, callee_args, depth + 1)
                sink_events.extend(callee_summary.sink_events)
                flags.update(callee_summary.flags)
                validations.update(callee_summary.validations)
                if callee_summary.return_provenances:
                    last_result = callee_summary.return_provenances
            elif not source_result and self.taint_engine.should_passthrough(target):
                last_result = cap_provenances(provenance for taints in arg_taints for provenance in taints)

            if target_name in {"setComponent", "setClass", "setClassName"} and sink_event:
                flags.add("intent_routing_configured")

        summary = MethodFlowSummary(
            return_provenances=(),
            sink_events=tuple(sink_events),
            flags=frozenset(flags),
            validations=frozenset(validations),
        )
        self._cache[cache_key] = summary
        self._stack.remove(cache_key)
        return summary

    def _source_for_call(
        self,
        method_ref: MethodRef,
        target: str,
        arg_taints: tuple[tuple[Provenance, ...], ...],
        const_args: tuple[object | None, ...],
    ) -> tuple[Provenance, ...] | None:
        target_name = _target_name(target)

        if target_name == "getIntent" and target.endswith(")Landroid/content/Intent;"):
            return (self.taint_engine.source_from_root(method_ref, "intent", "getIntent()"),)
        if target_name == "getExtras" and self._has_tag(arg_taints[:1], {"intent"}):
            return self._derive_provenances(
                method_ref,
                arg_taints[0],
                "bundle_extra",
                "getExtras()",
                preserve_origin=False,
                carry_validations=False,
            )
        if target_name in {"getStringExtra", "getString"} and self._has_tag(arg_taints[:1], {"intent", "bundle_extra"}):
            return self._derive_provenances(
                method_ref,
                arg_taints[0],
                "string_extra",
                self._call_detail(target_name, const_args[1] if len(const_args) > 1 else None),
                preserve_origin=False,
                carry_validations=False,
            )
        if target_name in {"getParcelableExtra", "getParcelable", "getParcelableArrayList"} and self._has_tag(
            arg_taints[:1], {"intent", "bundle_extra"}
        ):
            return self._derive_provenances(
                method_ref,
                arg_taints[0],
                "parcelable_extra",
                self._call_detail(target_name, const_args[1] if len(const_args) > 1 else None),
                preserve_origin=False,
                carry_validations=False,
            )
        if target_name in {"getSerializableExtra", "getSerializable"} and self._has_tag(arg_taints[:1], {"intent", "bundle_extra"}):
            return self._derive_provenances(
                method_ref,
                arg_taints[0],
                "serializable_extra",
                self._call_detail(target_name, const_args[1] if len(const_args) > 1 else None),
                preserve_origin=False,
                carry_validations=False,
            )
        if target_name == "getBundleExtra" and self._has_tag(arg_taints[:1], {"intent"}):
            return self._derive_provenances(
                method_ref,
                arg_taints[0],
                "bundle_extra",
                self._call_detail(target_name, const_args[1] if len(const_args) > 1 else None),
                preserve_origin=False,
                carry_validations=False,
            )
        if target_name in {"getData", "getDataString"} and self._has_tag(arg_taints[:1], {"intent"}):
            return self._derive_provenances(
                method_ref,
                arg_taints[0],
                "external_uri",
                f"{target_name}()",
                preserve_origin=False,
                carry_validations=False,
            )
        if target_name == "getQueryParameter" and self._has_tag(arg_taints[:1], {"external_uri"}):
            return self._derive_provenances(
                method_ref,
                arg_taints[0],
                "external_uri",
                self._call_detail(target_name, const_args[1] if len(const_args) > 1 else None),
                preserve_origin=False,
                carry_validations=False,
            )
        if target_name == "getHost" and self._has_tag(arg_taints[:1], {"external_uri"}):
            return self._derive_provenances(method_ref, arg_taints[0], "url_host", "getHost()")
        if target_name == "getScheme" and self._has_tag(arg_taints[:1], {"external_uri"}):
            return self._derive_provenances(method_ref, arg_taints[0], "url_scheme", "getScheme()")
        if target_name in {"getLastPathSegment", "getPath", "getPathSegments"} and self._has_tag(
            arg_taints[:1], {"provider_uri", "external_uri"}
        ):
            return self._derive_provenances(
                method_ref,
                arg_taints[0],
                "provider_path",
                f"{target_name}()",
                preserve_origin=False,
                carry_validations=False,
            )
        return None

    def _sink_for_call(
        self,
        method_ref: MethodRef,
        target: str,
        target_name: str,
        registers: tuple[str, ...],
        arg_taints: tuple[tuple[Provenance, ...], ...],
        intent_targets: dict[str, str],
        intent_actions: dict[str, str],
        intent_payload_taints: dict[str, tuple[Provenance, ...]],
        active_guards: list[GuardScope],
    ):
        if target_name in {"startActivity", "startActivityForResult", "startService", "sendBroadcast"}:
            route_taints = arg_taints[1:2] if len(arg_taints) > 1 else ()
            sink_reg = registers[1] if len(registers) > 1 else ""
            extra: dict[str, str] = {}
            if sink_reg in intent_targets:
                extra["target_component"] = intent_targets[sink_reg]
            if sink_reg in intent_actions:
                extra["intent_action"] = intent_actions[sink_reg]
            payload_taints = intent_payload_taints.get(sink_reg, ())
            if route_taints and route_taints[0]:
                extra["launch_control"] = "route_control"
                return self.taint_engine.build_sink_event(
                    "intent_launch_sink",
                    method_ref,
                    target,
                    route_taints[0],
                    f"{target_name}()",
                    extra=extra,
                )
            if payload_taints:
                extra["launch_control"] = "payload_only"
                return self.taint_engine.build_sink_event(
                    "intent_launch_sink",
                    method_ref,
                    target,
                    payload_taints,
                    f"{target_name}()",
                    extra=extra,
                )
            if sink_reg in intent_actions and sink_reg not in intent_targets and active_guards:
                control_taints = cap_provenances(
                    provenance
                    for guard in active_guards
                    for provenance in self._apply_active_guards(method_ref, guard.source_provenances, [guard])
                )
                if control_taints:
                    extra["launch_control"] = "implicit_guarded_route"
                    return self.taint_engine.build_sink_event(
                        "intent_launch_sink",
                        method_ref,
                        target,
                        control_taints,
                        f"{target_name}()",
                        extra=extra,
                    )
        if target_name in {"setComponent", "setClass", "setClassName"}:
            sink_taints = arg_taints[1:]
            if self._has_tag(sink_taints, {"string_extra", "external_uri", "serializable_extra", "parcelable_extra"}):
                return self.taint_engine.build_sink_event(
                    "intent_redirection_sink",
                    method_ref,
                    target,
                    cap_provenances(provenance for taints in sink_taints for provenance in taints),
                    f"{target_name}()",
                )
        if target_name in {"loadUrl", "evaluateJavascript", "postUrl"}:
            sink_taints = arg_taints[1:2] if len(arg_taints) > 1 else ()
            if self._has_tag(sink_taints, {"string_extra", "external_uri", "serializable_extra", "provider_path"}):
                return self.taint_engine.build_sink_event(
                    "webview_load_sink",
                    method_ref,
                    target,
                    sink_taints[0],
                    f"{target_name}()",
                )
        if target == "Ljava/io/File;-><init>(Ljava/lang/String;)V" and len(arg_taints) > 1:
            if self._has_tag(arg_taints[1:2], {"provider_path"}):
                return self.taint_engine.build_sink_event(
                    "provider_path_file_sink",
                    method_ref,
                    target,
                    arg_taints[1],
                    "File(path)",
                )
        if target == "Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V" and len(arg_taints) > 2:
            if self._has_tag(arg_taints[2:3], {"provider_path"}):
                return self.taint_engine.build_sink_event(
                    "provider_path_file_sink",
                    method_ref,
                    target,
                    arg_taints[2],
                    "File(parent, path)",
                )
        return None

    def _flag_for_call(self, target: str, const_args: tuple[object | None, ...]) -> str | None:
        if target == "Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V" and _is_true_arg(const_args, 1):
            return "webview_js_enabled"
        if target == "Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V" and _is_true_arg(const_args, 1):
            return "webview_allow_file_access"
        if target == "Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs(Z)V" and _is_true_arg(const_args, 1):
            return "webview_file_url_access"
        if target == "Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V" and _is_true_arg(
            const_args, 1
        ):
            return "webview_universal_file_access"
        if target == "Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V":
            return "webview_js_interface"
        return None

    def _pending_validation_for_call(
        self,
        method_ref: MethodRef,
        target_name: str,
        arg_taints: tuple[tuple[Provenance, ...], ...],
        const_args: tuple[object | None, ...],
    ) -> tuple[str, tuple[Provenance, ...], str] | None:
        if target_name not in BOOLEAN_VALIDATION_CALLS:
            return None
        flattened = cap_provenances(provenance for taints in arg_taints for provenance in taints)
        if not flattened:
            return None
        if not any(provenance.tag in {"string_extra", "external_uri", "provider_path", "url_host", "url_scheme"} for provenance in flattened):
            return None
        validation = self._classify_boolean_validation(target_name, flattened, const_args)
        return validation, flattened, f"{target_name}() check"

    def _immediate_validations_for_call(
        self,
        method_ref: MethodRef,
        target_name: str,
        registers: tuple[str, ...],
        arg_taints: tuple[tuple[Provenance, ...], ...],
    ) -> tuple[tuple[str, tuple[str, ...]], ...]:
        results: list[tuple[str, tuple[str, ...]]] = []
        if target_name == "setPackage" and registers[:1] and self._has_tag(arg_taints[:1], {"intent", "parcelable_extra"}):
            results.append(("package_lock_validation", registers[:1]))
        if target_name in {"setClass", "setComponent"} and registers[:1] and self._has_tag(
            arg_taints[:1], {"intent", "parcelable_extra"}
        ):
            results.append(("component_lock_validation", registers[:1]))
        if target_name in {"getCanonicalPath", "getCanonicalFile", "normalize"} and registers[:1] and self._has_tag(
            arg_taints[:1], {"provider_path"}
        ):
            results.append(("canonical_path_validation", registers[:1]))
        return tuple(results)

    def _annotate_registers(
        self,
        method_ref: MethodRef,
        reg_taints: dict[str, tuple[Provenance, ...]],
        registers: tuple[str, ...],
        validation: str,
        validations: set[str],
    ) -> None:
        for register in registers:
            taints = reg_taints.get(register, ())
            if not taints:
                continue
            reg_taints[register] = cap_provenances(
                self.taint_engine.annotate_validation(provenance, validation, method_ref, f"{validation} applied")
                for provenance in taints
            )
            validations.add(validation)

    def _collect_path_sensitive_validations(self, summary: MethodFlowSummary) -> set[str]:
        return {
            validation
            for sink in summary.sink_events
            for provenance in sink.provenances
            for validation in provenance.validations
        }

    def _update_intent_state(
        self,
        method_ref: MethodRef,
        target: str,
        target_name: str,
        registers: tuple[str, ...],
        arg_taints: tuple[tuple[Provenance, ...], ...],
        reg_taints: dict[str, tuple[Provenance, ...]],
        reg_classes: dict[str, str],
        reg_consts: dict[str, int | str],
        intent_targets: dict[str, str],
        intent_actions: dict[str, str],
        intent_payload_taints: dict[str, tuple[Provenance, ...]],
    ) -> str | None:
        if not registers:
            return None
        owner_reg = registers[0]
        if target == "Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V" and len(registers) >= 3:
            target_class = reg_classes.get(registers[2])
            if target_class:
                intent_targets[owner_reg] = target_class
            return None
        if target == "Landroid/content/Intent;-><init>(Ljava/lang/String;)V" and len(registers) >= 2:
            action = reg_consts.get(registers[1])
            if isinstance(action, str):
                intent_actions[owner_reg] = action
            return None
        if target == "Landroid/content/Intent;->setClass(Landroid/content/Context;Ljava/lang/Class;)Landroid/content/Intent;" and len(registers) >= 3:
            target_class = reg_classes.get(registers[2])
            if target_class:
                intent_targets[owner_reg] = target_class
            return owner_reg
        if target == "Landroid/content/Intent;->setClassName(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;" and len(registers) >= 3:
            class_name = reg_consts.get(registers[2])
            if isinstance(class_name, str):
                intent_targets[owner_reg] = f"L{class_name.replace('.', '/')};"
            return owner_reg
        if target_name == "putExtra" and len(registers) >= 3:
            key = reg_consts.get(registers[1])
            value_taints = arg_taints[2]
            if value_taints:
                detail = self._call_detail("putExtra", key)
                intent_payload_taints[owner_reg] = cap_provenances(
                    [
                        *intent_payload_taints.get(owner_reg, ()),
                        *(
                            self.taint_engine.derive(provenance, provenance.tag, method_ref, detail)
                            for provenance in value_taints
                        ),
                    ]
                )
            return owner_reg
        if target_name == "putExtras" and len(registers) >= 2 and arg_taints[1]:
            intent_payload_taints[owner_reg] = cap_provenances([*intent_payload_taints.get(owner_reg, ()), *arg_taints[1]])
            return owner_reg
        if target_name in {"setData", "setDataAndType"} and len(registers) >= 2 and arg_taints[1]:
            intent_payload_taints[owner_reg] = cap_provenances(
                [
                    *intent_payload_taints.get(owner_reg, ()),
                    *self._derive_provenances(method_ref, arg_taints[1], "external_uri", f"{target_name}()"),
                ]
            )
            return owner_reg
        return owner_reg if target.startswith("Landroid/content/Intent;->") and target.endswith(")Landroid/content/Intent;") else None

    def _apply_active_guards(
        self, method_ref: MethodRef, provenances: tuple[Provenance, ...], active_guards: list[GuardScope]
    ) -> tuple[Provenance, ...]:
        if not provenances or not active_guards:
            return provenances
        guarded = list(provenances)
        for guard in active_guards:
            for index, provenance in enumerate(guarded):
                if provenance.origin not in guard.origins or guard.validation in provenance.validations:
                    continue
                guarded[index] = self.taint_engine.annotate_validation(provenance, guard.validation, method_ref, guard.detail)
        return cap_provenances(guarded)

    def _branch_guard(
        self,
        method_ref: MethodRef,
        opcode: str,
        output: str,
        offset: int,
        registers: list[str],
        validation_registers: dict[str, tuple[str, tuple[Provenance, ...], str]],
    ) -> GuardScope | None:
        if opcode != "if-eqz" or not registers:
            return None
        pending = validation_registers.get(registers[0])
        if not pending:
            return None
        target = self._parse_branch_target(offset, output)
        if target is None or target <= offset:
            return None
        validation, source_provenances, detail = pending
        origins = frozenset(provenance.origin for provenance in source_provenances if provenance.origin)
        if not origins:
            return None
        return GuardScope(target, source_provenances, origins, validation, detail)

    def _parse_branch_target(self, offset: int, output: str) -> int | None:
        match = BRANCH_TARGET_RE.search(output.strip())
        if not match:
            return None
        raw = match.group(1)
        magnitude = raw[1:-1] if raw.endswith("h") else raw[1:]
        delta = int(magnitude, 16) if raw.endswith("h") else int(magnitude, 10)
        delta = delta * 2
        return offset + delta if raw.startswith("+") else offset - delta

    def _classify_boolean_validation(
        self, target_name: str, provenances: tuple[Provenance, ...], const_args: tuple[object | None, ...]
    ) -> str:
        literal = next((value for value in const_args if isinstance(value, str)), None)
        tags = {provenance.tag for provenance in provenances}
        if target_name in {"equals", "equalsIgnoreCase"}:
            if literal and ("url_host" in tags or "url_scheme" in tags):
                return "url_allowlist_validation"
            return "url_exact_match_validation"
        if target_name == "endsWith":
            if literal and literal.startswith(".") and "url_host" in tags:
                return "url_allowlist_validation"
            return "flawed_url_validation"
        if target_name == "startsWith":
            if literal and re.match(r"^https?://[^/]+/.+", literal):
                return "url_allowlist_validation"
            return "flawed_url_validation"
        if target_name in {"contains", "matches"}:
            return "flawed_url_validation"
        return "url_validation"

    def _call_detail(self, target_name: str, key: object | None) -> str:
        if isinstance(key, str) and key:
            return f"{target_name}({key})"
        return f"{target_name}()"

    def _derive_provenances(
        self,
        method_ref: MethodRef,
        source_provenances: tuple[Provenance, ...],
        new_tag: str,
        detail: str,
        preserve_origin: bool = True,
        carry_validations: bool = True,
    ) -> tuple[Provenance, ...]:
        if not source_provenances:
            return (self.taint_engine.source_from_root(method_ref, new_tag, detail),)
        return cap_provenances(
            self.taint_engine.derive(
                provenance,
                new_tag,
                method_ref,
                detail,
                preserve_origin=preserve_origin,
                carry_validations=carry_validations,
            )
            for provenance in source_provenances
        )

    def _parse_const_string(self, output: str) -> tuple[str, str] | None:
        match = CONST_STR_RE.match(output)
        if not match:
            return None
        return match.group(1), match.group(2)

    def _parse_const_number(self, output: str) -> tuple[str, int] | None:
        match = CONST_NUM_RE.match(output)
        if not match:
            return None
        raw = match.group(2)
        value = int(raw, 16) if raw.lower().startswith("0x") else int(raw)
        return match.group(1), value

    def _parse_single_register(self, output: str) -> str | None:
        match = SINGLE_REGISTER_RE.match(output)
        if not match:
            return None
        return match.group(1)

    def _parse_instance_field(self, output: str) -> tuple[str, str, str] | None:
        match = INSTANCE_FIELD_RE.match(output)
        if not match:
            return None
        return match.group(1), match.group(2), match.group(3)

    def _parse_static_field(self, output: str) -> tuple[str, str] | None:
        match = STATIC_FIELD_RE.match(output)
        if not match:
            return None
        return match.group(1), match.group(2)

    def _param_registers(self, method_ref: MethodRef) -> tuple[str, ...]:
        if self.dex is None:
            return ()
        method_analysis = self.dex.methods.get(method_ref.signature)
        if method_analysis is None:
            return ()
        info = method_analysis.get_method().get_information()
        return tuple(f"v{register}" for register, _ in info.get("params", ()))

    def _has_tag(self, taints: tuple[tuple[Provenance, ...], ...], expected: set[str]) -> bool:
        return any(provenance.tag in expected for reg_taints in taints for provenance in reg_taints)


def _target_name(target_signature: str) -> str:
    return target_signature.split("->", 1)[1].split("(", 1)[0]


def _is_true_arg(values: tuple[object | None, ...], index: int) -> bool:
    return len(values) > index and values[index] == 1
