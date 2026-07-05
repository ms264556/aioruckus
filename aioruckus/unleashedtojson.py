from __future__ import annotations
from functools import cache
import sys
import base64
import binascii
import xmltodict
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from .const import ERROR_POST_BADRESULT
from .exceptions import SchemaError

# --- Compatibility Blocks ---
if sys.version_info >= (3, 10):
    from types import UnionType
else:
    UnionType = object()
if sys.version_info >= (3, 11):
    from typing import (
        Any,
        NamedTuple,
        TypeVar,
        Union,
        cast,
        get_args,
        get_origin,
        get_type_hints,
        is_typeddict,
        overload,
    )
else:
    from typing_extensions import (
        Any,
        NamedTuple,
        TypeVar,
        Union,
        cast,
        get_args,
        get_origin,
        get_type_hints,
        is_typeddict,
        overload,
    )

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


# --- Type Inspection Logic ---
def _is_typeddict_like(hint: Any) -> bool:
    """Checks if a type is a TypedDict (or a schema we've generated from a Union of TypedDicts)."""
    return is_typeddict(hint) or getattr(hint, "_is_generated_schema", False)


def _extract_type_info(hint: Any) -> _TypeInfo:
    """
    Unpacks complex types like `List[Union[DictA, DictB]]` to find the
    underlying TypedDicts.
    """
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

    return _Plan(is_list=root_info.is_list, specs=tuple(specs))


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

    if (
        isinstance(result, dict)
        and "id" in result
        and "type" in result
        and result["type"] == "object"
    ):
        # The 'id' usually tells us which key holds the actual data
        payload_key = result["id"].split(".")[0]

        if payload_key == "stamgr":
            # Specific handling for 'stamgr' (Station Manager) data
            result = result.get("apstamgr-stat")
            if isinstance(result, dict) and len(result) == 1:
                result = next(iter(result.values()))
        elif payload_key in result:
            # Generic handling: find the key that matches the ID
            result = result[payload_key]
            if (
                payload_key.endswith("-list")
                and isinstance(result, dict)
                and len(result) == 1
            ):
                # Fixup: single item XML list
                result = next(iter(result.values()))
        elif "response" in result:
            result = result["response"]

        # Fixup: apply structure based on target_type
        if target_type and result:
            result = _restructure(target_type, result)

    return result or []


def _process_ruckus_xml(path, key, value):
    """Decrypt fields and rename keys."""
    if not path:
        return key, value

    if key.startswith("x-"):
        # Encrypted field: strip the 'x-' and decrypt
        return key[2:], _decrypt_value(key, value) if value else value

    if (
        key == "status"
        and path[-1][0] == "client"
        and value
        and isinstance(value, str)
        and value.isnumeric()
    ):
        # Normalize client status codes
        return key, {
            "1": "Authorized",
            "2": "Authenticating",
            "3": "PSK Expired",
            "4": "Authorized(Deny)",
            "5": "Authorized(Permit)",
        }.get(value, "Unauthorized")
    return key, value


def _decrypt_value(key: str, encrypted_string: str) -> str:
    """Decrypt AES/Caesar encrypted field values."""
    if (
        key == "x-password"
        and len(encrypted_string) >= 16
        and len(encrypted_string) % 4 == 0
        and all(c.isalnum() or c in "/+=" for c in encrypted_string)
    ):
        # Try AES
        try:
            encrypted_bytes = base64.b64decode(encrypted_string, validate=True)
            if len(encrypted_bytes) in (16, 32, 48):
                decryptor = Cipher(
                    algorithms.AES(key=b"Svdlvt`Jefoujgz`QXE`ALFZ"), modes.ECB()
                ).decryptor()
                padded_bytes = decryptor.update(encrypted_bytes) + decryptor.finalize()
                unpadder = PKCS7(128).unpadder()
                decrypted_bytes = unpadder.update(padded_bytes) + unpadder.finalize()
                return decrypted_bytes.decode("utf-8")
        except binascii.Error:
            pass  # Not AES, fall through to Caesar
    # Caesar
    return "".join(chr(ord(letter) - 1) for letter in encrypted_string)
