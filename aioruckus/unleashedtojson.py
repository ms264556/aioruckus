"""Convert Ruckus AJAX XML responses to dicts, driven by TypedDict definitions.

Rather than per-request list of collection element names (the old
`unwrap_xml(collection_elements=...)` approach), the target TypedDict
describes the desired structure, and ``parse_ajax_response`` recursively
restructures the parsed XML to match it: single XML list items are wrapped
into lists, empty lists are fixed up, and lists are trimmed using the
``num-<key>`` metadata the controller emits.
"""

from __future__ import annotations

import sys
from functools import cache

try:
    from types import UnionType
except ImportError:  # Python < 3.10
    UnionType = object()
from typing import (
    Any,
    NamedTuple,
    TypeVar,
    Union,
    cast,
    get_args,
    get_origin,
    get_type_hints,
    overload,
)

if sys.version_info >= (3, 10):
    from typing import is_typeddict
else:
    from typing_extensions import is_typeddict

import xmltodict

from .const import ERROR_POST_BADRESULT
from .exceptions import SchemaError
from .utility import _process_ruckus_xml

D = TypeVar("D")


# --- Internal Helper Structures ---
class _TypeInfo(NamedTuple):
    """Holds basic info extracted from a type hint."""

    is_list: bool
    types: list[type]


class _FieldSpec(NamedTuple):
    """Instructions for how to process a specific field in a dictionary."""

    key_name: str
    target_type: type
    is_list: bool


class _Plan(NamedTuple):
    """The 'Master Plan' for converting a specific TypedDict."""

    is_list: bool
    specs: tuple[_FieldSpec, ...]
    fields: frozenset[str] = frozenset()  # all declared field names


# --- Type Inspection Logic ---
def _is_typeddict_like(hint: Any) -> bool:
    """Checks if a type is a TypedDict (or a schema we've generated from a Union of TypedDicts)."""
    return is_typeddict(hint) or getattr(hint, "_is_generated_schema", False)


def _extract_type_info(hint: Any) -> _TypeInfo:
    """
    Unpacks complex types like `List[Union[DictA, DictB]]` to find the
    underlying TypedDicts.
    """
    # Bare `list` / `dict` (no subscription) are valid target types: they
    # mean "array" / "plain dict" passthrough, with no field specs.
    if hint is list:
        return _TypeInfo(is_list=True, types=[])
    if hint is dict:
        return _TypeInfo(is_list=False, types=[])

    # get_origin returns the base class (e.g., `list` from `list[int]`)
    origin = get_origin(hint)

    # Case 1: It's a List
    if origin is list:
        args = get_args(hint)  # Get what's inside the list
        inner_info = _extract_type_info(args[0])
        return _TypeInfo(is_list=True, types=inner_info.types)

    # Case 2: It's a Union (e.g., DictA | DictB)
    if origin in (Union, UnionType):
        args = get_args(hint)
        is_list_any = False
        found_types = []
        for arg in args:
            info = _extract_type_info(arg)
            if info.is_list:
                is_list_any = True
            found_types.extend(info.types)
        return _TypeInfo(is_list=is_list_any, types=found_types)

    # Case 3: It's a direct TypedDict
    if _is_typeddict_like(hint):
        return _TypeInfo(is_list=False, types=[hint])

    # Case 4: It's a primitive (int, str) or unknown -> Ignore it
    return _TypeInfo(is_list=False, types=[])


def _get_merged_schema(types_list: list[type]) -> type:
    """
    If a field allows multiple types (Union[A, B]), this creates a fake,
    combined TypedDict containing all possible keys from both A and B.
    We assume, since we control the inputs, that types are compatible.
    """
    types_list = list(set(types_list))
    if len(types_list) == 1:
        return types_list[0]

    merged_hints = {}
    names = []
    for t in types_list:
        names.append(t.__name__)
        merged_hints.update(get_type_hints(t))

    return type(
        f"Union_{'_'.join(names)}",
        (dict,),
        {"__annotations__": merged_hints, "_is_generated_schema": True},
    )


@cache
def _compile_plan(target_type: type) -> _Plan:
    """
    Analyze TypedDict.
    Returns a _Plan telling the code which fields need special handling
    (like converting a single dict to a list of dicts).
    """
    root_info = _extract_type_info(target_type)
    if not root_info.types:
        # It's a primitive type, no processing needed
        return _Plan(is_list=root_info.is_list, specs=())

    # Merge types if it's a Union, so we have one target schema to look at
    schema_type = _get_merged_schema(root_info.types)
    specs = []

    # Loop through every field defined in the TypedDict
    for field_name, field_hint in get_type_hints(schema_type).items():
        if field_hint is str:
            continue  # Strings don't need restructuring

        # Check if this field contains nested TypedDicts
        info = _extract_type_info(field_hint)
        if info.types:
            field_target = _get_merged_schema(info.types)
            # Record that this specific field needs processing later
            specs.append(
                _FieldSpec(
                    key_name=field_name,
                    target_type=field_target,
                    is_list=info.is_list,
                )
            )

    return _Plan(
        is_list=root_info.is_list,
        specs=tuple(specs),
        fields=frozenset(get_type_hints(schema_type)),
    )


# --- Data Restructuring Logic ---
def _restructure(target_type: type[D], data: Any, limit: int | None = None) -> D:
    """
    Recursively fix `data` to match the structure defined in `target_type`.
    """
    plan = _compile_plan(target_type)

    if plan.is_list:
        if data is None:
            # Fixup: empty XML list
            return cast(D, [])
        if isinstance(data, dict):
            # Fixup: single XML list item
            data = [data]
        if isinstance(data, str) and data and "," not in data:
            # Fixup: single id reference given as element text or attribute
            # (e.g. <wlansvc>1</wlansvc> or wlansvc="1"). A comma-separated
            # value is a list of ids, and an empty value means none, so both
            # are left for the caller to handle.
            data = [{"id": data}]
        if isinstance(data, list) and limit is not None:
            # Fixup: XML list with extra dummy records
            data = data[:limit]
        if isinstance(data, list):
            # Process TypedDict list items
            for item in data:
                if isinstance(item, dict):
                    _apply_specs(item, plan.specs)

    elif isinstance(data, dict):
        # Process TypedDict
        _apply_specs(data, plan.specs)

    return cast(D, data)


def _apply_specs(instance: dict, specs: tuple[_FieldSpec, ...]) -> None:
    """Helper to apply restructuring to specific keys in a dictionary."""
    for spec in specs:
        if spec.key_name not in instance:
            continue

        val = instance[spec.key_name]

        # Handle None values
        if val is None:
            if spec.is_list:
                instance[spec.key_name] = []
            continue

        # Check if the XML included a metadata key like "num-client-list"
        # to indicate a limit/count
        limit_val = instance.get(f"num-{spec.key_name}")
        if isinstance(limit_val, str) and limit_val.isdigit():
            limit = int(limit_val)
        else:
            limit = None

        # Determine the type for the next recursion step
        next_target = list[spec.target_type] if spec.is_list else spec.target_type

        # Recursion: Fix the nested data
        instance[spec.key_name] = _restructure(next_target, val, limit)

    # Special case: interval-stats cleanup
    if "interval-stats" in instance:
        raw = instance["interval-stats"]
        if raw is None:
            instance["interval-stats"] = []
        else:
            items = raw if isinstance(raw, list) else [raw]
            instance["interval-stats"] = [
                item for item in items
                if isinstance(item, dict) and item.get("time") != "0"
            ]


# --- Public API ---
@overload
def parse_ajax_response(xml: str, target_type: type[D]) -> D: ...


@overload
def parse_ajax_response(xml: str) -> dict | list[dict]: ...


def _unwrap_object_response(result: Any) -> Any:
    """Navigate the Ruckus ``type="object"`` wrapper to the payload.

    The ``id`` usually names the key holding the actual data (e.g. an
    updater tag like ``stamgr.…`` or a payload key like ``ap-list.…``);
    older controllers sometimes omit it, and docmd responses carry the
    payload directly (``xmsg``) with only a session-tag id.
    """
    if not isinstance(result, dict) or result.get("type") != "object":
        return result
    if "id" in result:
        payload_key = result["id"].split(".")[0]
        if payload_key == "stamgr":
            # Specific handling for 'stamgr' (Station Manager) data
            return result.get("apstamgr-stat")
        if payload_key in result:
            # Generic handling: find the key that matches the ID
            return result[payload_key]
    for key in ("response", "apstamgr-stat"):
        if key in result:
            # 'response' is the common wrapper; 'apstamgr-stat' covers the
            # session-tag ids (e.g. 'DEH') and older controllers without an id
            return result[key]
    # 'type' is only a marker on these responses; drop it so the
    # generic single-key unwrap below can reach the payload
    return {k: v for k, v in result.items() if k != "type"}


def parse_ajax_response(
    xml: str, target_type: type[D] | None = None
) -> D | dict | list[dict]:
    """
    Main entry point. Parses raw XML string into JSON/Dicts,
    navigates the specific Ruckus API wrapper structure,
    and applies type-based fixes.
    """
    # Parse XML string to dict, using custom processor for decryption/renaming
    result = xmltodict.parse(
        xml, encoding="utf-8", attr_prefix="", postprocessor=_process_ruckus_xml
    )

    # Remove standard Ruckus API wrapper.
    try:
        result = result["ajax-response"]["response"]
    except KeyError as kerr:
        raise SchemaError(ERROR_POST_BADRESULT) from kerr

    result = _unwrap_object_response(result)

    # Generic: unwrap any single-key wrapper — the <xxx-list> collection
    # root used by getconf/backup configs, and single-item list fixups.
    # But if that single key is a declared field of the target TypedDict
    # (e.g. a lone <sysinfo> or <time> section), keep it wrapped so
    # _restructure can apply the field's own conversion to its value.
    plan = _compile_plan(target_type) if target_type is not None else None
    while isinstance(result, dict) and len(result) == 1:
        key = next(iter(result))
        if plan is not None and key in plan.fields:
            break
        value = result[key]
        if value is not None and not isinstance(value, (dict, list)):
            break
        result = value

    # Fixup: apply structure based on target_type
    if target_type and result:
        result = _restructure(target_type, result)

    return result or []
