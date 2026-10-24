"""Bounded, caller-bound snapshots of already sanitized tool results.

Views are structural, not field whitelists or model-generated summaries. Every
omitted value has an exact read path; small objects are returned whole.
"""
from collections import OrderedDict
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
import secrets
import time
from typing import Any


PAGE_BYTES = 16_000
ITEM_BYTES = PAGE_BYTES - 1000
PREVIEW_BYTES = 6_000
MAX_RESULT_BYTES = 16_000_000
SECRET_RESULTS = {"create_key", "create_service_account_key", "regenerate_key", "regenerate_key_by_id"}


class ResultError(ValueError):
    pass


def encode(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def pointer(parent: str, key: str | int) -> str:
    return parent + "/" + str(key).replace("~", "~0").replace("/", "~1")


def select(value: Any, path: str) -> Any:
    if not path:
        return value
    if not path.startswith("/") or re.search(r"~(?![01])", path):
        raise ResultError("Use a JSON Pointer path returned by the result index.")
    try:
        for part in path[1:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if isinstance(value, list):
                if not re.fullmatch(r"0|[1-9][0-9]*", part):
                    raise ValueError
                value = value[int(part)]
            elif isinstance(value, dict):
                value = value[part]
            else:
                raise ValueError
    except (KeyError, IndexError, ValueError):
        raise ResultError("The result does not contain that path; browse its parent first.") from None
    return value


def kind(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, str):
        return "string"
    return "number"


def contains_credential(value: Any, *, source: str = "", path: tuple[str | int, ...] = ()) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            # Model-info reads use data[i].model_info.key for a catalog identifier.
            # Exempt only that field's name; still scan its value for credentials.
            catalog_key = (source in {"list_models", "get_model"} and len(path) == 3
                           and path[0] == "data" and isinstance(path[1], int)
                           and path[2] == "model_info" and key == "key")
            if (not catalog_key
                    and key.lower() in {"key", "api_key", "token", "access_token", "refresh_token", "password",
                                "secret", "client_secret", "authorization", "authentication_token"}
                    and isinstance(child, str) and child
                    and child not in {"[redacted]", "[credential redacted]"}
                    and not re.fullmatch(r"[a-f0-9]{64}", child)):
                return True
            if contains_credential(child, source=source, path=(*path, key)):
                return True
    elif isinstance(value, list):
        return any(contains_credential(v, source=source, path=(*path, i)) for i, v in enumerate(value))
    elif isinstance(value, str):
        if re.search(r"\bsk-[A-Za-z0-9_+-]+", value):
            return True
        try:
            nested = json.loads(value)
        except ValueError:
            return False
        if isinstance(nested, (dict, list)):
            return contains_credential(nested, source=source, path=path)
    return False


@dataclass(frozen=True)
class Snapshot:
    owner: bytes
    principal: str
    source: str
    raw: bytes
    deadline: float
    expires_at: float
    route: str | None = None


class ResultStore:
    def __init__(self, *, ttl: int = 300, max_bytes: int = 64_000_000, max_per_owner: int = 16):
        self.ttl, self.max_bytes, self.max_per_owner = ttl, max_bytes, max_per_owner
        self._salt = secrets.token_bytes(32)
        self._items: OrderedDict[str, Snapshot] = OrderedDict()
        self._bytes = 0

    def _owner(self, credential: str) -> bytes:
        return hmac.digest(self._salt, credential.encode(), hashlib.sha256)

    def _expire(self):
        now = time.monotonic()
        for token, item in list(self._items.items()):
            if item.deadline <= now:
                self._bytes -= len(item.raw)
                del self._items[token]

    def clear(self):
        self._items.clear()
        self._bytes = 0

    def put(self, source: str, value: Any, credential: str, principal: str, *, route: str | None = None) -> str | None:
        self._expire()
        raw = encode(value)
        # New credentials are delivered in the original full response, never
        # retained for later reads. Also exclude recognizable keys in log data.
        if source in SECRET_RESULTS or contains_credential(value, source=source) or contains_credential(route):
            return None
        owner = self._owner(credential)
        if (len(raw) > MAX_RESULT_BYTES or self._bytes + len(raw) > self.max_bytes
                or sum(s.owner == owner for s in self._items.values()) >= self.max_per_owner):
            # Do not evict an unexpired snapshot or lose a committed write's
            # response. The caller falls back to the complete inline result.
            return None
        token = secrets.token_urlsafe(24)
        self._items[token] = Snapshot(owner, principal, source, raw,
            time.monotonic() + self.ttl, time.time() + self.ttl, route)
        self._bytes += len(raw)
        return token

    def get(self, token: str, credential: str, principal: str) -> Snapshot:
        self._expire()
        item = self._items.get(token)
        if item is None or item.owner != self._owner(credential) or item.principal != principal:
            raise ResultError("Result unavailable to this caller or expired. Do not repeat a write to retrieve its response.")
        return item


def page(item: Snapshot, token: str, *, path: str = "", offset: int = 0,
         limit: int = 20, max_chars: int = 4000) -> dict:
    value = select(json.loads(item.raw), path)
    node_type = kind(value)
    result = {"format": "litellm-admin-page-v1", "result_id": token, "source_tool": item.source,
        "expires_at": item.expires_at, "path": path, "type": node_type,
        "read_tool": "read_admin_result", "full_read": {"result_id": token, "path": path, "view": "full"}}
    if not isinstance(value, (dict, list, str)):
        if offset:
            raise ResultError("Scalar values do not have offsets.")
        return {**result, "value": value, "complete": True}
    total = len(value)
    if offset > total:
        raise ResultError("Offset exceeds this node's length.")
    result.update(total=total, offset=offset)
    if isinstance(value, str):
        # Offsets count Unicode code points, not UTF-8 bytes or tokens.
        chunk = value[offset:offset + max_chars]
        result.update(value=chunk, offset_unit="unicode_code_points")
        end = offset + len(chunk)
        result["complete"] = offset == 0 and end == total
    else:
        entries, used = [], 0
        keys = list(value) if isinstance(value, dict) else range(total)
        for key in keys[offset:offset + limit]:
            child = value[key]
            child_path = pointer(path, key)
            entry = {"key" if isinstance(value, dict) else "index": key,
                     "path": child_path, "type": kind(child)}
            raw_size = len(encode(child))
            if raw_size <= ITEM_BYTES:
                entry.update(value=child, complete=True)
            else:
                if entries and PAGE_BYTES - used < PREVIEW_BYTES + 1000:
                    break
                entry.update(complete=False, read={"result_id": token, "path": child_path})
                if isinstance(child, (dict, list, str)):
                    entry["total"] = len(child)
                if isinstance(child, dict):
                    # Preserve whole small fields, including unknown metadata,
                    # null/0/false. The preview never pretends to be complete.
                    preview, omitted, remaining = {}, [], PREVIEW_BYTES
                    for field, val in child.items():
                        cost = len(encode({field: val}))
                        if cost <= remaining:
                            preview[field] = val
                            remaining -= cost
                        else:
                            omitted.append(field)
                    entry.update(preview=preview, omitted_fields=omitted[:20], omitted_count=len(omitted))
            cost = len(encode(entry))
            if entries and used + cost > PAGE_BYTES:
                break
            entries.append(entry)
            used += cost
        result["entries"] = entries
        end = offset + len(entries)
        result["complete"] = offset == 0 and end == total and all(e["complete"] for e in entries)
    result["has_more"] = end < total
    result["next"] = ({"result_id": token, "path": path, "offset": end,
                       "limit": limit, "max_chars": max_chars} if end < total else None)
    return result


RESPONSE_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {"view": {"type": "string", "enum": ["full", "compact"],
        "description": "full preserves the original result. compact keeps small results whole and pages large results without discarding data. Never repeat a write for a different view; use read_admin_result."}},
}

READ_SCHEMA = {
    "type": "object", "additionalProperties": False, "required": ["result_id"],
    "properties": {
        "result_id": {"type": "string"},
        "path": {"type": "string", "default": "", "description": "Exact JSON Pointer from an index; empty string selects the entire original result."},
        "view": {"type": "string", "enum": ["page", "full"], "default": "page"},
        "offset": {"type": "integer", "minimum": 0, "default": 0},
        "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20,
                  "description": "Object fields or array items per page."},
        "max_chars": {"type": "integer", "minimum": 1, "maximum": 16000, "default": 4000,
                      "description": "Unicode code points per string chunk; offset uses the same units."},
    },
}
