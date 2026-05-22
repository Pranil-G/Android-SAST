from __future__ import annotations

import re
from typing import Iterable

from .models import ManifestPermission, MethodRef, Provenance

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
REGISTER_RE = re.compile(r"\bv\d+\b")
INVOKE_TARGET_RE = re.compile(r"(L[^;]+;->[^\(]+\([^\)]*\).+)$")
CONST_CLASS_RE = re.compile(r"^(v\d+),\s*(L[^;]+;)$")

STRONG_ANDROID_PERMISSION_PREFIXES = (
    "android.permission.BIND_",
    "android.permission.MANAGE_",
)

STRONG_ANDROID_PERMISSION_NAMES = {
    "android.permission.INTERACT_ACROSS_USERS_FULL",
    "android.permission.WRITE_SECURE_SETTINGS",
    "android.permission.MASTER_CLEAR",
}

FRAMEWORK_PREFIXES = (
    "Landroid/",
    "Landroidx/",
    "Ljava/",
    "Ljavax/",
    "Lkotlin/",
    "Lkotlinx/",
    "Ldalvik/",
    "Lorg/apache/",
    "Lorg/json/",
    "Lorg/xml/",
    "Lcom/google/",
    "Lcom/android/",
    "Lokhttp3/",
    "Lokio/",
    "Lio/flutter/",
    "Lio/reactivex/",
)


def get_android_attr(element, name: str) -> str | None:
    return element.get(f"{ANDROID_NS}{name}")


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.lower() == "true"


def descriptor_from_java_name(name: str, package_name: str) -> str:
    if name.startswith("."):
        name = f"{package_name}{name}"
    elif "." not in name:
        name = f"{package_name}.{name}"
    return f"L{name.replace('.', '/')};"


def java_name_from_descriptor(descriptor: str) -> str:
    return descriptor.strip("L;").replace("/", ".")


def method_trace_line(method: MethodRef, detail: str) -> str:
    return f"{java_name_from_descriptor(method.class_name)}.{method.name}: {detail}"


def child_origin(origin: str, suffix: str) -> str:
    return f"{origin}>{suffix}" if origin else suffix


def cap_provenances(provenances: Iterable[Provenance], limit: int = 4) -> tuple[Provenance, ...]:
    unique: list[Provenance] = []
    seen = set()
    for provenance in provenances:
        if provenance in seen:
            continue
        unique.append(provenance)
        seen.add(provenance)
        if len(unique) >= limit:
            break
    return tuple(unique)


def protection_level_is_strong(permission_name: str | None, declared_permissions: dict[str, ManifestPermission]) -> bool:
    if not permission_name:
        return False
    declared = declared_permissions.get(permission_name)
    if declared and declared.protection_level:
        level = declared.protection_level.lower()
        return "signature" in level or "privileged" in level
    if permission_name.startswith("android.permission."):
        return permission_name in STRONG_ANDROID_PERMISSION_NAMES or permission_name.startswith(
            STRONG_ANDROID_PERMISSION_PREFIXES
        )
    return False


def classify_permission_level(permission_name: str | None, declared_permissions: dict[str, ManifestPermission]) -> str:
    if not permission_name:
        return "none"
    declared = declared_permissions.get(permission_name)
    if declared and declared.protection_level:
        level = declared.protection_level.lower()
        if "signature" in level or "privileged" in level:
            return "signature"
        if "dangerous" in level:
            return "dangerous"
        return "normal"
    if permission_name.startswith("android.permission."):
        if protection_level_is_strong(permission_name, declared_permissions):
            return "signature"
        return "normal"
    return "unknown"


def is_framework_class(descriptor: str) -> bool:
    return descriptor.startswith(FRAMEWORK_PREFIXES)


def parse_invoke_output(output: str) -> tuple[tuple[str, ...], str] | None:
    match = INVOKE_TARGET_RE.search(output)
    if not match:
        return None
    target = match.group(1).replace(" ", "")
    regs_part = output[: match.start()].rstrip(", ").strip()
    registers = tuple(REGISTER_RE.findall(regs_part))
    return registers, target


def parse_const_class(output: str) -> tuple[str, str] | None:
    match = CONST_CLASS_RE.match(output)
    if not match:
        return None
    return match.group(1), match.group(2)
