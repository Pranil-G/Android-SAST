from __future__ import annotations

from xml.etree import ElementTree as ET

from context_sast.helpers import descriptor_from_java_name, get_android_attr, parse_bool
from context_sast.models import ComponentInfo, IntentFilterData, IntentFilterInfo, ManifestAnalysis, ManifestPermission


class ManifestAnalyzer:
    def analyze(self, apk) -> ManifestAnalysis:
        xml = apk.get_android_manifest_xml()
        package_name = apk.get_package()
        min_sdk = _as_int(apk.get_min_sdk_version())
        target_sdk = _as_int(apk.get_target_sdk_version())

        permissions = self._extract_permissions(xml)
        components = self._extract_components(xml, package_name)

        return ManifestAnalysis(
            package_name=package_name,
            min_sdk=min_sdk,
            target_sdk=target_sdk,
            permissions=permissions,
            components=tuple(components),
        )

    def _extract_permissions(self, xml: ET.Element) -> dict[str, ManifestPermission]:
        permissions: dict[str, ManifestPermission] = {}
        for node in xml.findall("permission"):
            name = get_android_attr(node, "name")
            if not name:
                continue
            protection_level = get_android_attr(node, "protectionLevel")
            permissions[name] = ManifestPermission(name=name, protection_level=protection_level)
        return permissions

    def _extract_components(self, xml: ET.Element, package_name: str) -> list[ComponentInfo]:
        app = xml.find("application")
        if app is None:
            return []

        components: list[ComponentInfo] = []
        for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            for node in app.findall(tag):
                raw_name = get_android_attr(node, "name")
                if not raw_name:
                    continue

                intent_filters = tuple(self._parse_intent_filter(filter_node) for filter_node in node.findall("intent-filter"))
                exported_attr = get_android_attr(node, "exported")
                implicitly_exported = exported_attr is None and bool(intent_filters) and tag != "provider"
                exported_default = bool(intent_filters) if tag != "provider" else False
                exported = parse_bool(exported_attr, default=exported_default)
                authorities_raw = get_android_attr(node, "authorities") or ""

                components.append(
                    ComponentInfo(
                        name=descriptor_from_java_name(raw_name, package_name),
                        kind=tag,
                        exported=exported,
                        implicitly_exported=implicitly_exported,
                        permission=get_android_attr(node, "permission"),
                        read_permission=get_android_attr(node, "readPermission"),
                        write_permission=get_android_attr(node, "writePermission"),
                        grant_uri_permissions=parse_bool(get_android_attr(node, "grantUriPermissions")),
                        authorities=tuple(part.strip() for part in authorities_raw.split(";") if part.strip()),
                        intent_filters=intent_filters,
                    )
                )
        return components

    def _parse_intent_filter(self, node: ET.Element) -> IntentFilterInfo:
        actions = tuple(
            value for value in (get_android_attr(action, "name") for action in node.findall("action")) if value
        )
        categories = tuple(
            value for value in (get_android_attr(category, "name") for category in node.findall("category")) if value
        )
        data = tuple(
            IntentFilterData(
                scheme=get_android_attr(data_node, "scheme"),
                host=get_android_attr(data_node, "host"),
                path=get_android_attr(data_node, "path"),
                path_prefix=get_android_attr(data_node, "pathPrefix"),
                path_pattern=get_android_attr(data_node, "pathPattern"),
                mime_type=get_android_attr(data_node, "mimeType"),
            )
            for data_node in node.findall("data")
        )
        return IntentFilterInfo(actions=actions, categories=categories, data=data)


def _as_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None
